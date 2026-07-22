/*
    mp_bridge.cpp — fork-embedded mailbox bridge + test autopilot.
    See mp_bridge.h for the overview.  This is a port of the melonDS fork's
    BridgePump + apApply (melonDS/src/frontend/qt_sdl/EmuThread.cpp), with the
    ENet LAN transport replaced by a direct non-blocking TCP pair and input
    injection going through NDS_getProcessingUserInput() instead of a key mask.

    Everything runs on the emulation thread; sockets are non-blocking and
    drained/flushed with bounded work per frame (DeSmuME's run loop is
    single-threaded — a blocking call here would freeze emulation).
*/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#include "MMU.h"
#include "mem.h"
#include "NDSSystem.h"
#include "armcpu.h"

#include "mp_bridge.h"

// ---------------------------------------------------------------------------
// Emulated RAM accessors (retail DS: mask 0x3FFFFF) — melonDS apRd*/apWr8/apPtr.
// Direct array access on purpose: mailboxes are .bss data, never executed, so
// no JIT invalidation or IO dispatch is wanted (same as the melonDS fork).
// ---------------------------------------------------------------------------
static inline u32 apRd32(u32 a) { return T1ReadLong(MMU.MAIN_MEM, a & _MMU_MAIN_MEM_MASK32); }
static inline u16 apRd16(u32 a) { return T1ReadWord(MMU.MAIN_MEM, a & _MMU_MAIN_MEM_MASK16); }
static inline s16 apRd16s(u32 a) { return (s16)apRd16(a); }
static inline u8  apRd8(u32 a) { return T1ReadByte(MMU.MAIN_MEM, a & _MMU_MAIN_MEM_MASK); }
static inline void apWr8(u32 a, u8 v) { T1WriteByte(MMU.MAIN_MEM, a & _MMU_MAIN_MEM_MASK, v); }
static inline u8* apPtr(u32 a) { return &MMU.MAIN_MEM[a & _MMU_MAIN_MEM_MASK]; }
static inline void apWr32(u32 a, u32 v) { T1WriteLong(MMU.MAIN_MEM, a & _MMU_MAIN_MEM_MASK32, v); }

// ---------------------------------------------------------------------------
// Transport: one non-blocking TCP link (host listens :7820, joiner connects).
// Frame: [u16 len LE][payload]; payload = the melonDS bridge bundle.
// ---------------------------------------------------------------------------
namespace
{

const int MP_PORT = 7820;
const u32 MP_MAX_FRAME = 8192;

struct MpPeer
{
    SOCKET s = INVALID_SOCKET;
    bool up = false;
    std::vector<u8> rx, tx;
};

struct MpNet
{
    int mode = 0;               // 0 off, 1 host, 2 join
    char joinIP[64] = "127.0.0.1";
    SOCKET listener = INVALID_SOCKET;
    MpPeer peers[3];            // host: up to 3 clients (slot i = role 2+i);
                                // join: peers[0] = the host link
    bool connecting = false;    // join: non-blocking connect in flight
    bool freshPeer = false;     // a link just came up: pump must resend
                                // on-change channels (party/pkt) — their
                                // caches predate this peer, so it would
                                // otherwise NEVER receive our party
    u32 retryAt = 0;
    int assignedRole = 0;       // join: role handed out by the host (0xFF ctl frame)
    char myName[24] = "Player";
    char rname[5][24] = {{0}};   // lobby display name by role (1..4)
    u16 rping[5] = {0};          // that role's ping-to-host, ms
    u16 myPingMs = 0;            // our own measured ping to the host
    u32 pingSentAt = 0;          // GetTickCount at last ping send
    u32 lastPing = 0;
    u32 lastName = 0;

    void setName(const char* nm)
    {
        if (nm && nm[0]) { strncpy(myName, nm, 23); myName[23] = 0; }
    }
    void sendName(int myRole)
    {
        u8 buf[29]; int nl = (int)strlen(myName); if (nl > 23) nl = 23;
        buf[0] = 0xFE; buf[1] = (u8)myRole;
        buf[2] = (u8)(myPingMs & 0xFF); buf[3] = (u8)(myPingMs >> 8);
        buf[4] = (u8)nl; memcpy(buf + 5, myName, nl);
        sendAll(buf, 5 + nl);
        if (myRole >= 1 && myRole <= 4) { memcpy(rname[myRole], myName, nl); rname[myRole][nl] = 0; rping[myRole] = myPingMs; }
    }
    void sendPing(int myRole)   // clients ping the host
    {
        if (mode != 2 || !peers[0].up) return;
        pingSentAt = GetTickCount();
        u8 buf[6] = { 0xFD, (u8)myRole,
            (u8)(pingSentAt & 0xFF), (u8)((pingSentAt >> 8) & 0xFF),
            (u8)((pingSentAt >> 16) & 0xFF), (u8)((pingSentAt >> 24) & 0xFF) };
        enqueue(0, buf, 6);
    }

    int myRole() const { return (mode == 1) ? 1 : (assignedRole ? assignedRole : 2); }
    bool anyUp() const { for (int i = 0; i < 3; i++) if (peers[i].up) return true; return false; }

    static void setNonBlock(SOCKET s)
    {
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        BOOL nd = TRUE;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nd, sizeof(nd));
    }

    // ---- LAN discovery beacon (UDP :7821, shared cross-emulator format) ----
    SOCKET beaconTx = INVALID_SOCKET;
    SOCKET beaconRx = INVALID_SOCKET;
    u32 lastBeacon = 0;

    void startBeaconTx()
    {
        beaconTx = socket(AF_INET, SOCK_DGRAM, 0);
        if (beaconTx != INVALID_SOCKET) { BOOL b = TRUE; setsockopt(beaconTx, SOL_SOCKET, SO_BROADCAST, (const char*)&b, sizeof(b)); }
    }
    void beaconBroadcast(u8 players)
    {
        if (beaconTx == INVALID_SOCKET) return;
        u8 buf[32]; memset(buf, 0, sizeof(buf));
        memcpy(buf, "PLATMP", 6); buf[6] = 1; buf[7] = players;
        // advertise the host's chosen lobby name (Host dialog), not the PC name
        int nl = (int)strlen(myName);
        if (nl == 0) { memcpy(buf + 8, "Player", 6); }
        else memcpy(buf + 8, myName, (nl < 24) ? nl : 23);
        sockaddr_in a; memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET; a.sin_port = htons(7821); a.sin_addr.s_addr = INADDR_BROADCAST;
        sendto(beaconTx, (const char*)buf, 32, 0, (sockaddr*)&a, sizeof(a));
    }
    void startBeaconRx()
    {
        if (beaconRx != INVALID_SOCKET) return;
        beaconRx = socket(AF_INET, SOCK_DGRAM, 0);
        if (beaconRx == INVALID_SOCKET) return;
        BOOL yes = TRUE; setsockopt(beaconRx, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
        sockaddr_in a; memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET; a.sin_port = htons(7821); a.sin_addr.s_addr = INADDR_ANY;
        if (bind(beaconRx, (sockaddr*)&a, sizeof(a)) != 0) { closesocket(beaconRx); beaconRx = INVALID_SOCKET; return; }
        u_long nb = 1; ioctlsocket(beaconRx, FIONBIO, &nb);
    }

    void startHost()
    {
        mode = 1;
        start();
        startBeaconTx();
    }
    void joinTo(const char* ip)
    {
        mode = 2;
        if (ip && ip[0]) { strncpy(joinIP, ip, sizeof(joinIP)-1); joinIP[sizeof(joinIP)-1] = 0; }
        connecting = false; retryAt = 0;
        for (int i = 0; i < 3; i++) dropPeer(i);
    }

    void start()
    {
        if (mode == 1)
        {
            listener = socket(AF_INET, SOCK_STREAM, 0);
            if (listener == INVALID_SOCKET) return;
            BOOL yes = TRUE;
            setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
            sockaddr_in a; memset(&a, 0, sizeof(a));
            a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(MP_PORT);
            if (bind(listener, (sockaddr*)&a, sizeof(a)) != 0 || listen(listener, 3) != 0)
            {
                closesocket(listener); listener = INVALID_SOCKET; return;
            }
            setNonBlock(listener);
            printf("[BR] hosting on :%d\n", MP_PORT);
        }
    }

    void dropPeer(int i)
    {
        MpPeer& p = peers[i];
        if (p.s != INVALID_SOCKET) closesocket(p.s);
        p.s = INVALID_SOCKET;
        p.up = false;
        p.rx.clear();
        p.tx.clear();
        if (mode == 2) connecting = false;
    }

    void tick(u32 frame)
    {
        if (mode == 0) return;

        if (mode == 1 && listener != INVALID_SOCKET)
        {
            // accept into any free slot; slot i is role 2+i (stable across
            // reconnects, so a rejoining player gets its old role back)
            for (int i = 0; i < 3; i++)
            {
                if (peers[i].up) continue;
                SOCKET s = accept(listener, NULL, NULL);
                if (s == INVALID_SOCKET) break;
                setNonBlock(s);
                peers[i].s = s; peers[i].up = true; freshPeer = true;
                u8 ctl[4] = { 2, 0, 0xFF, (u8)(2 + i) };   // [len=2][0xFF][role]
                peers[i].tx.insert(peers[i].tx.end(), ctl, ctl + 4);
                printf("[BR] peer accepted -> role %d\n", 2 + i);
            }
        }
        else if (mode == 2 && !peers[0].up)
        {
            MpPeer& h = peers[0];
            if (connecting)
            {
                fd_set wr, ex; FD_ZERO(&wr); FD_ZERO(&ex);
                FD_SET(h.s, &wr); FD_SET(h.s, &ex);
                timeval tv = { 0, 0 };
                int r = select(0, NULL, &wr, &ex, &tv);
                if (r > 0 && FD_ISSET(h.s, &wr))
                {
                    h.up = true; connecting = false; freshPeer = true;
                    printf("[BR] connected to %s\n", joinIP);
                }
                else if (r > 0 && FD_ISSET(h.s, &ex))
                {
                    dropPeer(0);
                    retryAt = frame + 120;
                }
            }
            else if (frame >= retryAt)
            {
                h.s = socket(AF_INET, SOCK_STREAM, 0);
                if (h.s == INVALID_SOCKET) { retryAt = frame + 120; return; }
                setNonBlock(h.s);
                sockaddr_in a; memset(&a, 0, sizeof(a));
                a.sin_family = AF_INET; a.sin_port = htons(MP_PORT);
                inet_pton(AF_INET, joinIP, &a.sin_addr);
                int r = connect(h.s, (sockaddr*)&a, sizeof(a));
                if (r == 0) { h.up = true; printf("[BR] connected to %s\n", joinIP); }
                else if (WSAGetLastError() == WSAEWOULDBLOCK) connecting = true;
                else { dropPeer(0); retryAt = frame + 120; }
            }
        }

        for (int i = 0; i < 3; i++) { flush(i); pumpRecv(i); }
    }

    void enqueue(int i, const u8* p, u32 n)
    {
        MpPeer& pr = peers[i];
        if (!pr.up || n == 0 || n > MP_MAX_FRAME) return;
        if (pr.tx.size() > 512 * 1024) return;
        u8 hdr[2] = { (u8)(n & 0xFF), (u8)(n >> 8) };
        pr.tx.insert(pr.tx.end(), hdr, hdr + 2);
        pr.tx.insert(pr.tx.end(), p, p + n);
        flush(i);
    }

    void sendAll(const u8* p, u32 n)
    {
        for (int i = 0; i < 3; i++) enqueue(i, p, n);
    }

    void flush(int i)
    {
        MpPeer& p = peers[i];
        if (!p.up || p.tx.empty()) return;
        int r = ::send(p.s, (const char*)p.tx.data(), (int)p.tx.size(), 0);
        if (r > 0) p.tx.erase(p.tx.begin(), p.tx.begin() + r);
        else if (r == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) dropPeer(i);
    }

    void pumpRecv(int i)
    {
        MpPeer& p = peers[i];
        if (!p.up) return;
        char tmp[16384];
        for (;;)
        {
            int r = ::recv(p.s, tmp, sizeof(tmp), 0);
            if (r > 0) { p.rx.insert(p.rx.end(), tmp, tmp + r); if (p.rx.size() > 1024*1024) { dropPeer(i); return; } }
            else if (r == 0) { dropPeer(i); printf("[BR] peer %d closed\n", i); return; }
            else
            {
                if (WSAGetLastError() != WSAEWOULDBLOCK) { dropPeer(i); printf("[BR] peer %d error\n", i); }
                return;
            }
        }
    }

    u32 recvFrame(int i, u8* out, u32 outMax)
    {
        MpPeer& p = peers[i];
        if (p.rx.size() < 2) return 0;
        u32 n = (u32)p.rx[0] | ((u32)p.rx[1] << 8);
        if (n == 0 || n > MP_MAX_FRAME) { dropPeer(i); return 0; }
        if (p.rx.size() < 2 + n) return 0;
        u32 c = (n <= outMax) ? n : outMax;
        memcpy(out, p.rx.data() + 2, c);
        p.rx.erase(p.rx.begin(), p.rx.begin() + 2 + n);
        return c;
    }

    void shutdownAll()
    {
        for (int i = 0; i < 3; i++) dropPeer(i);
        if (listener != INVALID_SOCKET) { closesocket(listener); listener = INVALID_SOCKET; }
        mode = 0;
    }
};

MpNet gNet;

// ---------------------------------------------------------------------------
// Bridge pump state (verbatim melonDS BridgeSt)
// ---------------------------------------------------------------------------
struct BridgeSt
{
    bool armed = false;         // env said host/join
    u32 frame = 0;
    u32 disc = 0, ctl = 0;
    u32 exportBlk = 0, importBlk = 0, partyExp = 0, partyImp = 0;
    u32 pktExp = 0, pktImp = 0, owExp = 0, owImp = 0;
    u32 blkN = 0, partyN = 0;
    u32 blkSize = 0, partySize = 0, pktSize = 0;
    u8 beat = 0;
    std::vector<u8> lastParty, lastPkt;
    u32 dbgTx = 0, dbgRx = 0, dbgPktTx = 0, dbgPktRx = 0;

    /* Freshness-tracked peer roles, TWO tiers:
     *  - roleSeenAt: LOBBY presence — stamped by name frames (0xFE) too, so
     *    the roster shows players the moment they connect. Drives the lobby
     *    UI and the discovery beacon only.
     *  - gameSeenAt: IN-GAME presence — stamped ONLY when a game-data bundle
     *    (tag 1/2/3) from role r arrives, i.e. that player actually activated
     *    Wireless Play. Drives the ROM-visible peerMask/status; without the
     *    split, a player idling in the lobby made the game flash "wireless
     *    connected" the instant the local player activated. */
    u32 roleSeenAt[5] = { 0, 0, 0, 0, 0 };
    u32 gameSeenAt[5] = { 0, 0, 0, 0, 0 };

    u8 MaskOf(const u32* seen, int myRole) const
    {
        u8 m = 0;
        for (int r = 1; r <= 4; r++)
            if (r != myRole && seen[r] != 0 && frame - seen[r] <= 180)
                m |= (u8)(1u << (r - 1));
        return m;
    }
    u8 FreshPeerMask(int myRole) const { return MaskOf(roleSeenAt, myRole); }
    u8 GamePeerMask(int myRole)  const { return MaskOf(gameSeenAt, myRole); }
};
BridgeSt gBr;

// ---------------------------------------------------------------------------
// Autopilot state (port of the melonDS ap* namespace)
// ---------------------------------------------------------------------------
int apMode = -1;                // -1 off, 0 host, 1 join
int apHold = 0;
int patMode = 0;                // 0 walk, 1 run, 2 circle, 3 waggle, 4 ugclient, 5 ughost
u32 apFrame = 0;
u32 apConnFrame = 0;
int apInField = 0;
u32 apFieldFC = 0;
FILE* apCsv = NULL;

} // namespace

// ---------------------------------------------------------------------------

// ===========================================================================
// Win32 LAN lobby: Multiplayer menu -> Host / Join dialogs (name entry +
// auto-find list + direct IP) -> a modeless lobby window showing the player
// roster.  Drives the same TCP bridge as env, so it interoperates with the
// melonDS and BizHawk forks.  main.cpp forwards 3 messages.
// ===========================================================================
namespace {
enum { MP_ID_HOST = 0xE100, MP_ID_JOIN, MP_ID_STOP };
HMENU gMpMenu = NULL;
struct FoundHost { char ip[32]; char name[28]; u32 seen; };
FoundHost gFound[8]; int gFoundN = 0;
HWND gLobby = NULL;

void MpArm() { gBr.armed = true; printf("[BR] armed via menu: mode=%d\n", gNet.mode); fflush(stdout); }

void MpBrowsePoll()
{
    gNet.startBeaconRx();
    if (gNet.beaconRx == INVALID_SOCKET) return;
    for (;;) {
        u8 buf[64]; sockaddr_in from; int fl = sizeof(from);
        int r = recvfrom(gNet.beaconRx, (char*)buf, sizeof(buf), 0, (sockaddr*)&from, &fl);
        if (r < 8) break;
        if (memcmp(buf, "PLATMP", 6) != 0) continue;
        char ip[32]; strcpy(ip, inet_ntoa(from.sin_addr));
        char nm[28]; memset(nm, 0, sizeof(nm)); memcpy(nm, buf + 8, (r - 8 < 24) ? (r - 8) : 24);
        int idx = -1;
        for (int i = 0; i < gFoundN; i++) if (!strcmp(gFound[i].ip, ip)) { idx = i; break; }
        if (idx < 0 && gFoundN < 8) idx = gFoundN++;
        if (idx >= 0) { strncpy(gFound[idx].ip, ip, 31); strncpy(gFound[idx].name, nm, 27); gFound[idx].seen = 0; }
    }
    for (int i = 0; i < gFoundN; ) { if (++gFound[i].seen > 12) { gFound[i] = gFound[--gFoundN]; } else i++; }
}

// --- in-memory DLGTEMPLATE builder ---
void AddItem(BYTE*& p, DWORD style, short x, short y, short cx, short cy, WORD id, WORD cls, const wchar_t* text)
{
    p = (BYTE*)(((ULONG_PTR)p + 3) & ~(ULONG_PTR)3);
    DLGITEMTEMPLATE* it = (DLGITEMTEMPLATE*)p; p += sizeof(DLGITEMTEMPLATE);
    it->style = style | WS_CHILD | WS_VISIBLE; it->dwExtendedStyle = 0;
    it->x = x; it->y = y; it->cx = cx; it->cy = cy; it->id = id;
    *(WORD*)p = 0xFFFF; p += 2; *(WORD*)p = cls; p += 2;
    int n = 0; while (text[n]) { *(WCHAR*)p = text[n]; p += 2; n++; } *(WCHAR*)p = 0; p += 2;
    *(WORD*)p = 0; p += 2;
}
BYTE* BeginDlg(BYTE* buf, WORD cdit, short cx, short cy, const wchar_t* cap)
{
    BYTE* p = buf;
    DLGTEMPLATE* t = (DLGTEMPLATE*)p; p += sizeof(DLGTEMPLATE);
    t->style = DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_SETFONT;
    t->dwExtendedStyle = 0; t->cdit = cdit; t->x = 0; t->y = 0; t->cx = cx; t->cy = cy;
    *(WORD*)p = 0; p += 2; *(WORD*)p = 0; p += 2;
    int n = 0; while (cap[n]) { *(WCHAR*)p = cap[n]; p += 2; n++; } *(WCHAR*)p = 0; p += 2;
    *(WORD*)p = 8; p += 2;
    const wchar_t* fn = L"MS Shell Dlg"; n = 0; while (fn[n]) { *(WCHAR*)p = fn[n]; p += 2; n++; } *(WCHAR*)p = 0; p += 2;
    return p;
}

// --- lobby window (modeless) ---
INT_PTR CALLBACK LobbyProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_INITDIALOG: SetTimer(h, 1, 500, NULL); return TRUE;
    case WM_TIMER: {
        char st[96];
        if (gNet.mode == 1) _snprintf(st, sizeof(st), "Hosting on port 7820 - waiting for players");
        else _snprintf(st, sizeof(st), "%s %s", gNet.anyUp() ? "Connected to" : "Connecting to", gNet.joinIP);
        SetDlgItemTextA(h, 200, st);
        HWND lb = GetDlgItem(h, 201);
        SendMessageA(lb, LB_RESETCONTENT, 0, 0);
        int me = gNet.myRole(); u8 mask = gBr.FreshPeerMask(me);
        for (int r = 1; r <= 4; r++) {
            bool present = (r == me) || (mask & (1 << (r - 1)));
            if (!present) continue;
            char line[80];
            const char* nm = (r == me) ? gNet.myName : (gNet.rname[r][0] ? gNet.rname[r] : "");
            char who[32]; if (!nm[0]) _snprintf(who, sizeof(who), "Player %d", r); else { strncpy(who, nm, 31); who[31]=0; }
            if (r == me && gNet.mode == 2)
                              _snprintf(line, sizeof(line), "%s (you)  -  %u ms", who, gNet.myPingMs);
            else if (r == me) _snprintf(line, sizeof(line), "%s (you)", who);
            else if (r == 1)  _snprintf(line, sizeof(line), "%s (host)", who);
            else              _snprintf(line, sizeof(line), "%s  -  %u ms", who, gNet.rping[r]);
            SendMessageA(lb, LB_ADDSTRING, 0, (LPARAM)line);
        }
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(w) == IDCANCEL || LOWORD(w) == IDOK) {
            KillTimer(h, 1);
            gNet.shutdownAll(); gNet.mode = 0; gBr.armed = false;
            DestroyWindow(h); gLobby = NULL; return TRUE;
        }
        break;
    case WM_CLOSE:
        KillTimer(h, 1); gNet.shutdownAll(); gNet.mode = 0; gBr.armed = false;
        DestroyWindow(h); gLobby = NULL; return TRUE;
    }
    return FALSE;
}
void OpenLobby(HWND parent)
{
    if (gLobby) { SetForegroundWindow(gLobby); return; }
    static BYTE buf[1024]; memset(buf, 0, sizeof(buf));
    BYTE* p = BeginDlg(buf, 4, 190, 150, L"Wireless Lobby");
    // the lobby stays open for the whole session — let players minimize it
    ((DLGTEMPLATE*)buf)->style |= WS_MINIMIZEBOX;
    AddItem(p, SS_LEFT, 8, 8, 174, 10, 200, 0x0082, L"Starting...");
    AddItem(p, WS_BORDER | LBS_NOINTEGRALHEIGHT, 8, 22, 174, 100, 201, 0x0083, L"");
    AddItem(p, WS_TABSTOP | BS_DEFPUSHBUTTON, 70, 128, 50, 14, IDCANCEL, 0x0080, L"Leave");
    AddItem(p, SS_LEFT, 8, 130, 60, 10, 202, 0x0082, L"Use Wireless Play in-game.");
    gLobby = CreateDialogIndirectParamA(GetModuleHandle(NULL), (LPCDLGTEMPLATEA)buf, parent, LobbyProc, 0);
    ShowWindow(gLobby, SW_SHOW);
}

// --- host dialog (name entry) ---
static char gDlgName[24];
INT_PTR CALLBACK HostProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_INITDIALOG) { SetDlgItemTextA(h, 100, gNet.myName); SetFocus(GetDlgItem(h, 100)); return FALSE; }
    if (m == WM_COMMAND) {
        if (LOWORD(w) == IDOK) { GetDlgItemTextA(h, 100, gDlgName, sizeof(gDlgName)); EndDialog(h, 1); return TRUE; }
        if (LOWORD(w) == IDCANCEL) { EndDialog(h, 0); return TRUE; }
    }
    return FALSE;
}
// --- join dialog (name + list + direct IP) ---
INT_PTR CALLBACK JoinProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_INITDIALOG:
        SetDlgItemTextA(h, 100, gNet.myName);
        SetDlgItemTextA(h, 102, gNet.joinIP);
        SetTimer(h, 2, 700, NULL);
        return FALSE;
    case WM_TIMER: {
        MpBrowsePoll();
        HWND lb = GetDlgItem(h, 101);
        int sel = (int)SendMessageA(lb, LB_GETCURSEL, 0, 0);
        SendMessageA(lb, LB_RESETCONTENT, 0, 0);
        for (int i = 0; i < gFoundN; i++) {
            char line[80]; _snprintf(line, sizeof(line), "%s  (%s)", gFound[i].name, gFound[i].ip);
            SendMessageA(lb, LB_ADDSTRING, 0, (LPARAM)line);
        }
        if (sel >= 0 && sel < gFoundN) SendMessageA(lb, LB_SETCURSEL, sel, 0);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(w) == IDOK) {
            GetDlgItemTextA(h, 100, gDlgName, sizeof(gDlgName));
            char ip[64] = {0};
            int sel = (int)SendMessageA(GetDlgItem(h, 101), LB_GETCURSEL, 0, 0);
            if (sel >= 0 && sel < gFoundN) strncpy(ip, gFound[sel].ip, 63);
            else GetDlgItemTextA(h, 102, ip, sizeof(ip));
            if (!ip[0]) { MessageBoxA(h, "Pick a game or enter an IP.", "Join", MB_OK); return TRUE; }
            strncpy(gDlgName + 24, "", 0);  // noop keep
            lstrcpynA((LPSTR)gNet.joinIP, ip, sizeof(gNet.joinIP));
            KillTimer(h, 2); EndDialog(h, 1); return TRUE;
        }
        if (LOWORD(w) == IDCANCEL) { KillTimer(h, 2); EndDialog(h, 0); return TRUE; }
        break;
    }
    return FALSE;
}
bool ShowHostDialog(HWND parent)
{
    static BYTE buf[1024]; memset(buf, 0, sizeof(buf));
    BYTE* p = BeginDlg(buf, 4, 180, 62, L"Host LAN Game");
    AddItem(p, SS_LEFT, 8, 8, 160, 10, (WORD)-1, 0x0082, L"Your name:");
    AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 8, 22, 164, 12, 100, 0x0081, L"");
    AddItem(p, WS_TABSTOP | BS_DEFPUSHBUTTON, 60, 42, 56, 14, IDOK, 0x0080, L"Host Game");
    AddItem(p, WS_TABSTOP | BS_PUSHBUTTON, 122, 42, 50, 14, IDCANCEL, 0x0080, L"Cancel");
    return DialogBoxIndirectParamA(GetModuleHandle(NULL), (LPCDLGTEMPLATEA)buf, parent, HostProc, 0) == 1;
}
bool ShowJoinDialog(HWND parent)
{
    static BYTE buf[1536]; memset(buf, 0, sizeof(buf));
    BYTE* p = BeginDlg(buf, 7, 200, 150, L"Join LAN Game");
    AddItem(p, SS_LEFT, 8, 8, 80, 10, (WORD)-1, 0x0082, L"Your name:");
    AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 88, 6, 104, 12, 100, 0x0081, L"");
    AddItem(p, SS_LEFT, 8, 24, 184, 10, (WORD)-1, 0x0082, L"LAN games found:");
    AddItem(p, WS_BORDER | WS_TABSTOP | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT, 8, 36, 184, 70, 101, 0x0083, L"");
    AddItem(p, SS_LEFT, 8, 110, 60, 10, (WORD)-1, 0x0082, L"or IP address:");
    AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 70, 108, 122, 12, 102, 0x0081, L"");
    AddItem(p, WS_TABSTOP | BS_DEFPUSHBUTTON, 74, 130, 50, 14, IDOK, 0x0080, L"Join");
    // Cancel shares the row via IDCANCEL implicit (Esc) — add explicit:
    return DialogBoxIndirectParamA(GetModuleHandle(NULL), (LPCDLGTEMPLATEA)buf, parent, JoinProc, 0) == 1;
}
} // namespace

void MpBridge_InstallMenu(HWND mainWnd)
{
    HMENU bar = GetMenu(mainWnd);
    if (!bar) return;
    gMpMenu = CreatePopupMenu();
    AppendMenuA(gMpMenu, MF_STRING, MP_ID_HOST, "&Host LAN Game...");
    AppendMenuA(gMpMenu, MF_STRING, MP_ID_JOIN, "&Join LAN Game...");
    AppendMenuA(gMpMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(gMpMenu, MF_STRING, MP_ID_STOP, "Dis&connect");
    InsertMenuA(bar, (UINT)-1, MF_BYPOSITION | MF_POPUP, (UINT_PTR)gMpMenu, "&Multiplayer");
    DrawMenuBar(mainWnd);
}

void MpBridge_OnInitPopup(HMENU menu)
{
    if (menu != gMpMenu) return;
    EnableMenuItem(gMpMenu, MP_ID_HOST, MF_BYCOMMAND | (gNet.mode ? MF_GRAYED : MF_ENABLED));
    EnableMenuItem(gMpMenu, MP_ID_JOIN, MF_BYCOMMAND | (gNet.mode ? MF_GRAYED : MF_ENABLED));
    EnableMenuItem(gMpMenu, MP_ID_STOP, MF_BYCOMMAND | (gNet.mode ? MF_ENABLED : MF_GRAYED));
}

bool MpBridge_HandleCommand(unsigned int id)
{
    HWND w = GetActiveWindow();
    if (id == MP_ID_HOST) {
        if (ShowHostDialog(w)) { gNet.setName(gDlgName); gNet.startHost(); MpArm(); OpenLobby(w); }
        return true;
    }
    if (id == MP_ID_JOIN) {
        gFoundN = 0;
        if (ShowJoinDialog(w) && gNet.joinIP[0]) { gNet.setName(gDlgName); gNet.joinTo(gNet.joinIP); MpArm(); OpenLobby(w); }
        return true;
    }
    if (id == MP_ID_STOP) {
        if (gLobby) { DestroyWindow(gLobby); gLobby = NULL; }
        gNet.shutdownAll(); gNet.mode = 0; gBr.armed = false; return true;
    }
    return false;
}

void MpBridge_InitFromEnv()
{
    const char* e = getenv("MELONDS_AP");     // name kept for harness compat
    if (!e) return;
    if (!strcmp(e, "host")) { apMode = 0; gNet.mode = 1; }
    else if (!strcmp(e, "join")) { apMode = 1; gNet.mode = 2; }
    else return;

    const char* ip = getenv("MELONDS_AP_IP");
    if (ip) { strncpy(gNet.joinIP, ip, sizeof(gNet.joinIP) - 1); gNet.joinIP[sizeof(gNet.joinIP)-1] = 0; }
    apHold = getenv("MELONDS_AP_HOLD") ? 1 : 0;
    const char* pat = getenv("MELONDS_AP_PATTERN");
    patMode = (!pat) ? 0 : (!strcmp(pat, "run")) ? 1
            : (!strcmp(pat, "circle")) ? 2
            : (!strcmp(pat, "waggle")) ? 3
            : (!strcmp(pat, "ugclient")) ? 4
            : (!strcmp(pat, "ughost")) ? 5 : 0;

    gBr.armed = true;
    if (gNet.mode == 1) gNet.startHost(); else gNet.start();
    printf("[BR] armed: %s pattern=%d\n", (apMode == 0) ? "host" : "join", patMode);
    fflush(stdout);
}

void MpBridge_Shutdown()
{
    gNet.shutdownAll();
    if (apCsv) { fclose(apCsv); apCsv = NULL; }
}

// ---------------------------------------------------------------------------
// Per-frame pump — melonDS BridgePump ported.
// ---------------------------------------------------------------------------
void MpBridge_Pump()
{
    if (!gBr.armed) return;
    gBr.frame++;

    gNet.tick(gBr.frame);

    // A peer link just came up: drop the on-change send caches so the next
    // pump resends party/pkt to everyone.  Without this a peer connecting
    // AFTER our first send NEVER received our party — the receiving side's
    // battle/trade launch waits on partner party bytes forever ("the
    // accepter never gets the message").
    if (gNet.freshPeer)
    {
        gNet.freshPeer = false;
        gBr.lastParty.clear();
        gBr.lastPkt.clear();
    }

    // ROM discovery: scan periodically until found. Must NOT gate the
    // transport exchange below — the lobby connects at the title screen,
    // long before the game runs Multiplayer_Update()/InitDiscovery() in the
    // overworld and publishes the discovery block.
    if (!gBr.disc && (gBr.frame % 60) == 0)
    {
        for (u32 off = 0; off < 0x400000 - 16; off += 4)
        {
            if (T1ReadLong(MMU.MAIN_MEM, off) == 0xCAFE1234
                && T1ReadLong(MMU.MAIN_MEM, off + 4) == 0x5678CAFE)
            {
                gBr.disc = 0x02000000 + off;
                printf("[AP] discovery at %08X\n", gBr.disc);
                gBr.exportBlk = apRd32(gBr.disc + 2*4);
                gBr.importBlk = apRd32(gBr.disc + 3*4);
                gBr.partyExp  = apRd32(gBr.disc + 4*4);
                gBr.partyImp  = apRd32(gBr.disc + 5*4);
                gBr.pktExp    = apRd32(gBr.disc + 12*4);
                gBr.pktImp    = apRd32(gBr.disc + 13*4);
                gBr.owExp     = apRd32(gBr.disc + 14*4);
                gBr.owImp     = apRd32(gBr.disc + 15*4);
                gBr.blkSize   = apRd32(gBr.disc + 20*4) & 0xFFFF;
                gBr.blkN      = apRd32(gBr.disc + 25*4);
                gBr.partyN    = apRd32(gBr.disc + 26*4);
                gBr.ctl       = apRd32(gBr.disc + 31*4);
                break;
            }
        }
    }
    if (gBr.disc && !gBr.ctl)
        gBr.ctl = apRd32(gBr.disc + 31*4);   // [31] published after the sig
    bool romUp = (gBr.ctl != 0 && apRd32(gBr.ctl) == 0x42524731);
    if (romUp)
    {
        gBr.partySize = apRd16(gBr.ctl + 10);
        gBr.pktSize   = apRd16(gBr.ctl + 12);
        apWr8(gBr.ctl + 6, ++gBr.beat);   // fork heartbeat
    }

    if (gNet.mode == 1 && (gBr.frame - gNet.lastBeacon) >= 60) {
        gNet.lastBeacon = gBr.frame;
        gNet.beaconBroadcast((u8)(gBr.FreshPeerMask(gNet.myRole()) ? 2 : 1));
    }
    if (gNet.anyUp() && (gNet.mode == 1 || gNet.assignedRole)
        && (gBr.frame - gNet.lastName) >= 30) {
        gNet.lastName = gBr.frame;
        gNet.sendName(gNet.myRole());
    }
    if (gNet.mode == 2 && (gBr.frame - gNet.lastPing) >= 30) {
        gNet.lastPing = gBr.frame;
        gNet.sendPing(gNet.myRole());
    }

    int myRole = gNet.myRole();
    u8 wanted = romUp ? apRd8(gBr.ctl + 4) : 0;
    bool inGame = (romUp && wanted && gBr.blkSize != 0 && gBr.blkSize <= 512
        && gBr.partySize != 0 && gBr.partySize <= 2048
        && gBr.pktSize != 0 && gBr.pktSize <= 2048);

    // NOTE: no early-return when the ROM side isn't up yet. The lobby connects
    // and exchanges name/ping frames at the title screen, so the recv loop
    // below must run every armed frame or joined players never appear in the
    // lobby roster. Everything touching ROM RAM is gated on romUp/inGame.
    if (romUp)
    {
        apWr8(gBr.ctl + 8, (u8)myRole);
        if (!inGame)
        {
            apWr8(gBr.ctl + 7, 0);
            apWr8(gBr.ctl + 9, 0);
            gBr.lastParty.clear();
            gBr.lastPkt.clear();
        }
    }

    if (inGame && gNet.anyUp())
    {
        static std::vector<u8> buf;
        buf.resize(4 + 2048 + 48);

        // bundle: [1][role][blkSize u16][block][ow 48] — every frame
        buf[0] = 1; buf[1] = (u8)myRole;
        buf[2] = (u8)(gBr.blkSize & 0xFF); buf[3] = (u8)(gBr.blkSize >> 8);
        memcpy(buf.data() + 4, apPtr(gBr.exportBlk), gBr.blkSize);
        memcpy(buf.data() + 4 + gBr.blkSize, apPtr(gBr.owExp), 48);
        gNet.sendAll(buf.data(), 4 + gBr.blkSize + 48); gBr.dbgTx++;

        // party: on content change
        if (gBr.lastParty.size() != gBr.partySize
            || memcmp(gBr.lastParty.data(), apPtr(gBr.partyExp), gBr.partySize) != 0)
        {
            gBr.lastParty.assign(apPtr(gBr.partyExp), apPtr(gBr.partyExp) + gBr.partySize);
            buf[0] = 2; buf[1] = (u8)myRole;
            buf[2] = (u8)(gBr.partySize & 0xFF); buf[3] = (u8)(gBr.partySize >> 8);
            memcpy(buf.data() + 4, gBr.lastParty.data(), gBr.partySize);
            gNet.sendAll(buf.data(), 4 + gBr.partySize);
        }

        // pkt channel: on content change
        if (gBr.lastPkt.size() != gBr.pktSize
            || memcmp(gBr.lastPkt.data(), apPtr(gBr.pktExp), gBr.pktSize) != 0)
        {
            gBr.lastPkt.assign(apPtr(gBr.pktExp), apPtr(gBr.pktExp) + gBr.pktSize);
            buf[0] = 3; buf[1] = (u8)myRole;
            buf[2] = (u8)(gBr.pktSize & 0xFF); buf[3] = (u8)(gBr.pktSize >> 8);
            memcpy(buf.data() + 4, gBr.lastPkt.data(), gBr.pktSize);
            gNet.sendAll(buf.data(), 4 + gBr.pktSize); gBr.dbgPktTx++;
        }
    }

    // receive: apply peers' mailboxes (per peer link; host relays)
    {
        u8 rx[MP_MAX_FRAME];
        u32 n;
        for (int pi = 0; pi < 3; pi++)
        while ((n = gNet.recvFrame(pi, rx, sizeof(rx))) > 0)
        {
            gBr.dbgRx++;
            if (n == 2 && rx[0] == 0xFF)
            {
                // control: host-assigned role (joiner side)
                gNet.assignedRole = rx[1];
                gNet.sendName(gNet.myRole());   // announce our name on join
                continue;
            }
            if (n == 6 && rx[0] == 0xFD) {
                // client ping -> echo back as pong on the same peer link
                u8 pong[6]; memcpy(pong, rx, 6); pong[0] = 0xFC;
                gNet.enqueue(pi, pong, 6);
                continue;
            }
            if (n == 6 && rx[0] == 0xFC) {
                // pong for our ping: RTT = now - stamped tick
                u32 tick = rx[2] | (rx[3] << 8) | (rx[4] << 16) | ((u32)rx[5] << 24);
                u32 rtt = GetTickCount() - tick;
                gNet.myPingMs = (rtt > 9999) ? 9999 : (u16)rtt;
                continue;
            }
            if (n >= 5 && rx[0] == 0xFE) {
                // lobby name announce: [0xFE][role][ping16][len][name]
                int r2 = rx[1]; u16 png = (u16)(rx[2] | (rx[3] << 8)); int nl = rx[4];
                if (r2 >= 1 && r2 <= 4 && nl <= 23 && (u32)n >= (u32)(5 + nl)) {
                    memcpy(gNet.rname[r2], rx + 5, nl); gNet.rname[r2][nl] = 0; gNet.rping[r2] = png;
                    gBr.roleSeenAt[r2] = gBr.frame;
                    if (myRole == 1) for (int pj = 0; pj < 3; pj++) if (pj != pi) gNet.enqueue(pj, rx, n);
                }
                continue;
            }
            if (n < 4) continue;
            int tag = rx[0], r = rx[1];
            u32 sz = (u32)(rx[2] | (rx[3] << 8));
            if (r < 1 || r > 4 || r == myRole) continue;
            if (n < 4 + sz) continue;

            // Host relay: clients only reach the host — forward every client
            // bundle to the other clients so they see EACH OTHER (the origin
            // ignores its own echo via the r == myRole check).
            if (myRole == 1)
                for (int pj = 0; pj < 3; pj++)
                    if (pj != pi) gNet.enqueue(pj, rx, n);

            gBr.roleSeenAt[r] = gBr.frame;
            if (tag >= 1 && tag <= 3)
            {
                // Peer NEWLY game-active (just activated Wireless Play, or
                // reconnected): resend our on-change channels — anything we
                // sent before this moment predates their readiness.
                bool wasFresh = gBr.gameSeenAt[r] != 0 && gBr.frame - gBr.gameSeenAt[r] <= 180;
                if (!wasFresh)
                {
                    gBr.lastParty.clear();
                    gBr.lastPkt.clear();
                }
                gBr.gameSeenAt[r] = gBr.frame;
            }

            // Game-mailbox apply whenever the ROM's discovery block is up
            // (romUp) — NOT gated on our own activation: the mailboxes are
            // inert BSS until the ROM activates, and dropping pre-activation
            // frames LOST the peer's one-shot on-change party send when they
            // activated before us (the accepter never activated: its battle/
            // trade launch waits on partner party bytes forever).
            //
            // LEGACY-CHANNEL PAIR ROUTING (3+ players): the single pairwise
            // import block / party buffer must only receive the CHOSEN pair
            // partner's data — the ROM publishes its intent in the OW export
            // (pairRole @ +0x18; 0 = unpaired, keep first-come legacy
            // behaviour).  Without this every peer's bundle overwrote the
            // legacy block (last writer wins) and battle/trade/give requests
            // "broadcast" to every player.  Per-role arrays always update.
            if (romUp && tag == 1 && sz == gBr.blkSize && n >= 4 + sz + 48)
            {
                u8 pairRole = apRd8(gBr.owExp + 0x18);
                rx[4 + 0x12] = (u8)r;   // stamp playerRole (the old hub did this;
                                        // MpPartnerIsLead is dead without it)
                if (pairRole == 0 || r == (int)pairRole)
                    memcpy(apPtr(gBr.importBlk), rx + 4, sz);
                if (gBr.blkN) memcpy(apPtr(gBr.blkN + (r-1)*sz), rx + 4, sz);
                memcpy(apPtr(gBr.owImp + (r-1)*48), rx + 4 + sz, 48);
            }
            else if (romUp && tag == 2 && sz == gBr.partySize)
            {
                u8 pairRole = apRd8(gBr.owExp + 0x18);
                if (pairRole == 0 || r == (int)pairRole)
                    memcpy(apPtr(gBr.partyImp), rx + 4, sz);
                if (gBr.partyN) memcpy(apPtr(gBr.partyN + (r-1)*sz), rx + 4, sz);
            }
            else if (romUp && tag == 3 && sz == gBr.pktSize)
            {
                memcpy(apPtr(gBr.pktImp + (r-1)*sz), rx + 4, sz);
                gBr.dbgPktRx++;
            }
        }
    }

    if (inGame)
    {
        // GAME peer mask, not the lobby one: "connected" must mean the peer
        // is actually streaming game data (activated Wireless Play), not
        // merely sitting in the lobby.
        u8 pm = gBr.GamePeerMask(myRole);
        apWr8(gBr.ctl + 7, pm ? 2 : 1);   // status
        apWr8(gBr.ctl + 9, pm);           // peerMask
    }

    if ((gBr.frame % 120) == 0)
    {
        printf("[BR] f=%u role=%d wanted=%u lobby=%u game=%u tx=%u rx=%u pktTx=%u pktRx=%u\n",
            gBr.frame, myRole, wanted, gBr.FreshPeerMask(myRole), gBr.GamePeerMask(myRole),
            gBr.dbgTx, gBr.dbgRx, gBr.dbgPktTx, gBr.dbgPktRx);
        fflush(stdout);
    }

    // ALWAYS-ON crash catcher: overworld frame counter frozen while a session
    // is wanted => the ARM9 is wedged/crashed; dump registers for the map.
    if (romUp)
    {
        static u32 ccLastFC = 0, ccChangedAt = 0;
        static int ccDumped = 0;
        u32 fcNow = apRd32(gBr.owExp + 0x0C);
        if (fcNow != ccLastFC)
        {
            ccLastFC = fcNow;
            ccChangedAt = gBr.frame;
            ccDumped = 0;
        }
        else if (wanted && gBr.frame - ccChangedAt > 180 && ccDumped < 24)
        {
            FILE* cf = fopen("desmume_hangpc_auto.txt", "a");
            if (cf)
            {
                fprintf(cf, "role=%d f=%u FCstuck=%u R15=%08X R14=%08X R13=%08X R12=%08X CPSR=%08X\n",
                    myRole, gBr.frame, fcNow,
                    NDS_ARM9.instruct_adr, NDS_ARM9.R[14], NDS_ARM9.R[13], NDS_ARM9.R[12],
                    NDS_ARM9.CPSR.val);
                fprintf(cf, "  regs R0-11:");
                for (int ri = 0; ri < 12; ri++) fprintf(cf, " %08X", NDS_ARM9.R[ri]);
                fprintf(cf, "\n  banked SVC=%08X,%08X ABT=%08X,%08X IRQ=%08X,%08X\n",
                    NDS_ARM9.R13_svc, NDS_ARM9.R14_svc,
                    NDS_ARM9.R13_abt, NDS_ARM9.R14_abt,
                    NDS_ARM9.R13_irq, NDS_ARM9.R14_irq);
                u32 sp = NDS_ARM9.R13_abt ? NDS_ARM9.R13_abt : NDS_ARM9.R13_svc;
                if (!sp || (sp >> 24) != 0x02) sp = NDS_ARM9.R13_svc;
                if (sp && (sp >> 24) == 0x02)
                {
                    fprintf(cf, "  stack@%08X:", sp);
                    for (int si = 0; si < 32; si++)
                        fprintf(cf, " %08X", apRd32(sp + si*4));
                    fprintf(cf, "\n");
                }
                fclose(cf);
                ccDumped++;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Autopilot input — melonDS apApply ported onto UserInput.
// press bits follow the melonDS numbering: 0=A 1=B 2=Select 3=Start
// 4=Right 5=Left 6=Up 7=Down 10=X 11=Y.
// ---------------------------------------------------------------------------
void MpAp_OverrideInput()
{
    if (apMode < 0) return;
    apFrame++;

    u32 press = 0;

    // ---- boot script: A through title/continue until the field runs ----
    if (apFrame >= 700 && apFrame < 2000 && !apInField)
    {
        if ((apFrame % 40) < 8) press |= (1 << 0);
    }
    else if (!apHold && apFrame == 2120 && gBr.disc)
    {
        // debug-inbox activation (cmd 19): the SELECT shortcut is gone —
        // in-game activation lives on the "Wireless Play" bag item now.
        u32 inbox = apRd32(gBr.disc + 17*4);
        if (inbox)
        {
            apWr32(inbox + 12, 19);
            apWr32(inbox + 16, 1);
            apWr32(inbox + 4, apRd32(inbox + 8) + 1);
        }
    }

    if (gBr.disc)
    {
        u32 pOwExp = gBr.owExp;
        u32 pDiag = apRd32(gBr.disc + 30*4);
        // IN-GAME session mask (wm-diag peerMask), NOT the TCP link state:
        // patterns must wait for "Activate Multiplayer" to have completed.
        // (Latching on gNet.peerMask() fired at the title screen and ran the
        // whole script against a solo session.)
        u8 peerMask = pDiag ? apRd8(pDiag + 7) : 0;

        // field detection: overworld frameCounter advancing == in-field
        if (!apInField)
        {
            u32 fc = apRd32(pOwExp + 0x0C);
            if (fc != 0 && apFieldFC != 0 && fc != apFieldFC) apInField = 1;
            apFieldFC = fc;
        }

        if (!apConnFrame && peerMask)
        {
            apConnFrame = apFrame;
            printf("[AP] connected at frame %u\n", apFrame);
            fflush(stdout);
        }

        if (apConnFrame && !apHold)
        {
            u32 cf = apFrame - apConnFrame;
            u32 winLo = (apMode == 0) ? 300u : 1700u;
            u32 winHi = (apMode == 0) ? 1500u : 2900u;

            if (patMode >= 4)
            {
                // Underground leave/re-enter repro (the manual recipe):
                //   both: Y (registered Explorer Kit) then A every 1s x30 -> descend
                //   leaver only: X menu, Down x5, A x4 (2s apart) -> "Go up"
                //   wait ~15s, then Y + A every 1s x30 -> descend again
                // ugclient: the JOIN instance leaves; ughost: the HOST leaves.
                bool leaver = (patMode == 4) ? (apMode == 1) : (apMode == 0);
                // 4-player: extra joiners set MELONDS_AP_NOLEAVE=1 and stand.
                static int apNoLeave = -1;
                if (apNoLeave < 0) apNoLeave = getenv("MELONDS_AP_NOLEAVE") ? 1 : 0;
                if (apNoLeave) leaver = false;

                if (cf >= 300 && cf < 308)
                    press |= (1u << 11);                                   // Y: Explorer Kit
                else if (cf >= 360 && cf < 360 + 30*60 && ((cf - 360) % 60) < 8)
                    press |= (1u << 0);                                    // A x30 (1/s)

                if (leaver)
                {
                    const u32 L = 2400;                                    // below by now
                    const u32 R = L + 240 + 4*120 + 900;                   // after up + ~15s
                    if (cf >= L && cf < L + 8)
                        press |= (1u << 10);                               // X: menu
                    else if (cf >= L + 60 && cf < L + 60 + 5*24 && ((cf - L - 60) % 24) < 8)
                        press |= (1u << 7);                                // Down x5
                    else if (cf >= L + 240 && cf < L + 240 + 4*120 && ((cf - L - 240) % 120) < 8)
                        press |= (1u << 0);                                // A x4 (2s apart)
                    else if (cf >= R && cf < R + 8)
                        press |= (1u << 11);                               // Y again
                    else if (cf >= R + 60 && cf < R + 60 + 30*60 && ((cf - R - 60) % 60) < 8)
                        press |= (1u << 0);                                // A x30: re-descend
                }
            }
            else if (cf >= winLo && cf < winHi)
            {
                if (patMode == 3)
                {
                    u32 pc = (cf - winLo) % 510;
                    int bitA = (apMode == 0) ? 5 : 6;
                    int bitB = (apMode == 0) ? 4 : 7;
                    if (pc < 240)
                    {
                        press |= (1 << 1);
                        press |= (1 << (((pc / 8) & 1) ? bitA : bitB));
                    }
                    else if (pc < 420)
                    {
                        press |= (1 << 1);
                        press |= (1 << ((((cf - winLo) / 510) & 1) ? bitB : bitA));
                    }
                }
                else if (patMode == 2)
                {
                    static const int circleBit[4] = { 4, 7, 5, 6 };
                    press |= (1 << 1);
                    press |= (1 << circleBit[(cf / 32) & 3]);
                }
                else
                {
                    if (patMode == 1) press |= (1 << 1);
                    if (apMode == 0)
                        press |= (1 << (((cf / 90) & 1) ? 5 : 4));
                    else
                        press |= (1 << (((cf / 90) & 1) ? 7 : 6));
                }
            }
        }

        // telemetry CSV
        if (!apCsv)
        {
            char name[64];
            snprintf(name, sizeof(name), "desmume_ap_%s.csv", (apMode == 0) ? "host" : "join");
            apCsv = fopen(name, "w");
            if (apCsv) fprintf(apCsv, "frame,peerMask,ownX,ownZ,ownFC,i0FC,i1FC\n");
        }
        if (apCsv && gBr.owExp && gBr.owImp)
        {
            fprintf(apCsv, "%u,%u,%d,%d,%u,%u,%u\n",
                apFrame, peerMask,
                apRd16s(gBr.owExp + 4), apRd16s(gBr.owExp + 6), apRd32(gBr.owExp + 0x0C),
                apRd32(gBr.owImp + 0x0C), apRd32(gBr.owImp + 48 + 0x0C));
            if ((apFrame & 255) == 0) fflush(apCsv);
        }

        // per-role hang sampler (game FC frozen while connected)
        {
            static u32 lastFC = 0, lastChangeAt = 0, dumped = 0;
            u32 fcNow = apRd32(pOwExp + 0x0C);
            if (fcNow != lastFC) { lastFC = fcNow; lastChangeAt = apFrame; dumped = 0; }
            else if (apConnFrame && apFrame - lastChangeAt > 180 && dumped < 64)
            {
                char hn[64];
                snprintf(hn, sizeof(hn), "desmume_hangpc_%s.txt", (apMode == 0) ? "host" : "join");
                FILE* hf = fopen(hn, "a");
                if (hf)
                {
                    fprintf(hf, "f=%u FCstuck=%u R15=%08X R14=%08X R13=%08X R12=%08X CPSR=%08X\n",
                        apFrame, fcNow,
                        NDS_ARM9.instruct_adr, NDS_ARM9.R[14], NDS_ARM9.R[13], NDS_ARM9.R[12],
                        NDS_ARM9.CPSR.val);
                    fclose(hf);
                    dumped++;
                }
            }
        }
    }

    if (!press) return;

    UserInput& in = NDS_getProcessingUserInput();
    if (press & (1 << 0))  in.buttons.A = true;
    if (press & (1 << 1))  in.buttons.B = true;
    if (press & (1 << 2))  in.buttons.T = true;   // select
    if (press & (1 << 3))  in.buttons.S = true;   // start
    if (press & (1 << 4))  in.buttons.R = true;   // d-pad right
    if (press & (1 << 5))  in.buttons.L = true;   // d-pad left
    if (press & (1 << 6))  in.buttons.U = true;
    if (press & (1 << 7))  in.buttons.D = true;
    if (press & (1 << 10)) in.buttons.X = true;
    if (press & (1 << 11)) in.buttons.Y = true;
}
// MARKER_TEST
