// Mailbox bridge (see mp_bridge.h). Runs on the emulation thread, so sockets never block.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wctype.h>
#include <vector>
#include <string>

#include "MMU.h"
#include "mem.h"
#include "NDSSystem.h"
#include "armcpu.h"

#include "mp_bridge.h"
#include "winutil.h"   // IniName: persist the last-used relay server

// Emulated main RAM accessors. Direct array access: the mailboxes are plain data, no JIT or IO dispatch wanted.
static inline u32 apRd32(u32 a) { return T1ReadLong(MMU.MAIN_MEM, a & _MMU_MAIN_MEM_MASK32); }
static inline u16 apRd16(u32 a) { return T1ReadWord(MMU.MAIN_MEM, a & _MMU_MAIN_MEM_MASK16); }
static inline s16 apRd16s(u32 a) { return (s16)apRd16(a); }
static inline u8  apRd8(u32 a) { return T1ReadByte(MMU.MAIN_MEM, a & _MMU_MAIN_MEM_MASK); }
static inline void apWr8(u32 a, u8 v) { T1WriteByte(MMU.MAIN_MEM, a & _MMU_MAIN_MEM_MASK, v); }
static inline u8* apPtr(u32 a) { return &MMU.MAIN_MEM[a & _MMU_MAIN_MEM_MASK]; }
static inline void apWr32(u32 a, u32 v) { T1WriteLong(MMU.MAIN_MEM, a & _MMU_MAIN_MEM_MASK32, v); }

// Names arrive from other machines: blank out control characters before showing or logging them.
static void mpCleanName(char* s)
{
    for (; *s; s++) if ((unsigned char)*s < 0x20 || *s == 0x7F) *s = '?';
}

// Transport: non-blocking TCP (host listens :7820). Frame = [u16 len LE][payload].
namespace
{

const int MP_PORT = 7820;
const u32 MP_MAX_FRAME = 8192;
const int MP_RELAY_PORT = 7833;   // default port of the PMRELAY1 relay server
const u8  MP_WIRE_VER = 2;        // wire version: LAN beacon byte AND relay handshake (2 = 8-player rooms)
// Default relay for the online dialogs; a saved custom value wins.
const char* MP_DEFAULT_RELAY = "193.122.236.144:7833";

// Hosting needs an inbound firewall rule; if ours is missing we ask, then add it with one admin prompt.
const wchar_t* MP_FW_RULE = L"DeSmuME (Project PM)";

static void mpFwLower(std::wstring& s)
{
    for (size_t i = 0; i < s.size(); i++) s[i] = towlower(s[i]);
}

static bool mpFwRulePresent(const wchar_t* exe)
{
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules",
        0, KEY_READ, &k) != ERROR_SUCCESS) return false;

    // rule values are pipe-delimited tokens: v2.x|Action=Allow|...|App=path|...|Name=...|
    std::wstring wantPort = L"|lport="; wantPort += std::to_wstring(MP_PORT); wantPort += L"|";
    std::wstring wantName = L"|name="; wantName += MP_FW_RULE; wantName += L"|";
    std::wstring wantApp  = L"|app=";  wantApp  += exe;        wantApp  += L"|";
    mpFwLower(wantName); mpFwLower(wantApp);

    bool found = false;
    wchar_t name[256]; BYTE data[4096];
    for (DWORD i = 0; !found; i++)
    {
        DWORD nl = 256, dl = sizeof(data) - 2, type = 0;
        LONG r = RegEnumValueW(k, i, name, &nl, NULL, &type, data, &dl);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS || type != REG_SZ) continue;
        data[dl] = 0; data[dl + 1] = 0;
        std::wstring v((const wchar_t*)data);
        mpFwLower(v);
        found = v.find(wantName) != std::wstring::npos
             && v.find(wantApp)  != std::wstring::npos
             && v.find(wantPort) != std::wstring::npos   // older builds opened every port
             && v.find(L"|protocol=6|")   != std::wstring::npos
             && v.find(L"|action=allow|") != std::wstring::npos
             && v.find(L"|dir=in|")       != std::wstring::npos
             && v.find(L"|active=true|")  != std::wstring::npos;
    }
    RegCloseKey(k);
    return found;
}

static void mpEnsureFirewall()
{
    static bool once = false;
    if (once) return;
    once = true;

    wchar_t exe[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, exe, MAX_PATH);
    if (!n || n >= MAX_PATH) return;

    if (mpFwRulePresent(exe)) { printf("[BR] firewall rule ok\n"); return; }

    if (MessageBoxW(NULL,
        L"To let friends join your hosted game, Windows Firewall needs an\n"
        L"inbound rule for this emulator on TCP port 7820 (without it,\n"
        L"players outside your PC usually can't connect even with the port\n"
        L"forwarded).  Any existing firewall rules for this emulator are\n"
        L"replaced by it.\n\n"
        L"Add the rule now?  Windows will show one administrator prompt.",
        L"Project PM - enable hosting", MB_YESNO | MB_ICONQUESTION) != IDYES)
    {
        printf("[BR] firewall rule declined by user\n");
        return;
    }

    // Full System32 paths: this runs elevated, so nothing may be found by name.
    wchar_t sys[MAX_PATH];
    UINT sn = GetSystemDirectoryW(sys, MAX_PATH);
    if (!sn || sn >= MAX_PATH) return;
    std::wstring cmd = std::wstring(sys) + L"\\cmd.exe";

    // The delete clears the block rule a declined Windows prompt leaves behind.
    wchar_t args[1600];
    swprintf(args, 1600,
        L"/s /c \"\"%ls\\netsh.exe\" advfirewall firewall delete rule name=all program=\"%ls\" & "
        L"\"%ls\\netsh.exe\" advfirewall firewall add rule name=\"%ls\" dir=in action=allow "
        L"program=\"%ls\" protocol=TCP localport=%d enable=yes profile=any\"",
        sys, exe, sys, MP_FW_RULE, exe, MP_PORT);
    HINSTANCE rc = ShellExecuteW(NULL, L"runas", cmd.c_str(), args, sys, SW_SHOWMINNOACTIVE);
    printf("[BR] firewall rule %s\n",
        ((INT_PTR)rc > 32) ? "repair launched" : "not added (admin prompt declined)");
}

struct MpPeer
{
    SOCKET s = INVALID_SOCKET;
    bool up = false;
    bool authed = true;         // false while a password host waits for the joiner's password
    u32 upAt = 0;               // GetTickCount at accept
    u32 ip = 0;
    std::vector<u8> rx, tx;
};

struct MpNet
{
    int mode = 0;               // 0 off, 1 host, 2 join
    char joinIP[64] = "127.0.0.1";
    SOCKET listener = INVALID_SOCKET;
    MpPeer peers[7];            // host: slot i = role 2+i; join: peers[0] = the host link
    bool connecting = false;    // join: non-blocking connect in flight
    bool freshPeer = false;     // a link just came up: resend party/pkt next pump
    u32 retryAt = 0;
    int assignedRole = 0;       // join: role handed out by the host (0xFF ctl frame)
    char myName[24] = "Player";
    char rname[9][24] = {{0}};   // lobby display name by role (1..4)
    u16 rping[9] = {0};          // that role's ping-to-host, ms
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
        if (myRole >= 1 && myRole <= 8) { memcpy(rname[myRole], myName, nl); rname[myRole][nl] = 0; rping[myRole] = myPingMs; }
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
    bool anyUp() const { for (int i = 0; i < 7; i++) if (peers[i].up && peers[i].authed) return true; return false; }

    // ---- direct-hosting password (LAN / direct IP only; online rooms use the room code) ----
    char password[32] = "";     // host: required from joiners; joiner: sent on connect
    int authFail = 0;           // joiner: 1 = wrong password, 2 = host needs one
    struct Ban { u32 ip = 0; int fails = 0; u32 until = 0; } bans[16];
    int banNext = 0;

    void setPassword(const char* pw)
    {
        strncpy(password, pw ? pw : "", sizeof(password) - 1);
        password[sizeof(password) - 1] = 0;
    }
    // Five failed joins from one address lock it out for five minutes.
    bool ipBlocked(u32 ip)
    {
        for (Ban& b : bans)
            if (b.ip == ip && b.fails >= 5)
            {
                if ((int)(b.until - GetTickCount()) > 0) return true;
                b.fails = 0;
            }
        return false;
    }
    void noteFail(u32 ip)
    {
        Ban* b = NULL;
        for (Ban& c : bans) if (c.ip == ip) { b = &c; break; }
        if (!b) { b = &bans[banNext]; banNext = (banNext + 1) % 16; b->ip = ip; b->fails = 0; }
        b->fails++;
        b->until = GetTickCount() + 300000;
    }
    // Tell the joiner why (1 wrong password, 2 password required), then drop it.
    void rejectPeer(int i, u8 reason)
    {
        u8 f[4] = { 2, 0, 0xFA, reason };
        ::send(peers[i].s, (const char*)f, 4, 0);
        noteFail(peers[i].ip);
        printf("[BR] peer %d refused (%s)\n", i, reason == 1 ? "wrong password" : "no password sent");
        dropPeer(i);
    }
    // Host: the first frame from an unauthenticated peer must be [0xFB][0][len][password].
    void checkPassword(int i, const u8* rx, u32 n)
    {
        if (n < 3 || rx[0] != 0xFB) return;   // anything else waits for the timeout
        size_t want = strlen(password);
        u8 diff = (u8)(rx[2] ^ want);
        if (rx[2] == want && n >= 3 + want)
            for (size_t k = 0; k < want; k++) diff |= (u8)(rx[3 + k] ^ (u8)password[k]);
        else diff = 1;
        if (diff) { rejectPeer(i, 1); return; }
        peers[i].authed = true; freshPeer = true;
        u8 ctl[4] = { 2, 0, 0xFF, (u8)(2 + i) };
        peers[i].tx.insert(peers[i].tx.end(), ctl, ctl + 4);
        printf("[BR] peer %d password ok -> role %d\n", i, 2 + i);
    }
    // Joiner: send our password as the first frame on a direct link.
    void sendPassword()
    {
        size_t nl = strlen(password);
        if (!nl) return;
        u8 f[3 + sizeof(password)] = { 0xFB, 0, (u8)nl };
        memcpy(f + 3, password, nl);
        enqueue(0, f, (u32)(3 + nl));
    }
    // Host: slot i may only speak as role 2+i. Joiners trust the host's relay.
    bool roleAllowed(int slot, int role) const { return mode != 1 || role == 2 + slot; }

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
        memcpy(buf, "PLATMP", 6); buf[6] = MP_WIRE_VER; buf[7] = players;
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
        mpEnsureFirewall();
        mode = 1;
        start();
        startBeaconTx();
    }
    void joinTo(const char* ip)
    {
        mode = 2;
        if (ip && ip[0]) { strncpy(joinIP, ip, sizeof(joinIP)-1); joinIP[sizeof(joinIP)-1] = 0; }
        connecting = false; retryAt = 0; authFail = 0;
        for (int i = 0; i < 7; i++) dropPeer(i);
    }

    // Online relay mode (PMRELAY1): everyone dials out, the relay splices host and joiner into a normal game stream.
    int onlineMode = 0;             // 0 LAN/direct, 1 relay host, 2 relay join
    char relayDisp[160] = "";       // relay server as typed (display/config)
    sockaddr_in relayAddr;          // resolved once at start (UI/env thread)
    char roomCode[8] = "";          // host: relay-assigned; joiner: entered
    char relayStatus[96] = "";      // one-line state for the lobby UI
    bool relayFatal = false;        // terminal handshake error: stop retrying

    SOCKET ctlSock = INVALID_SOCKET;   // host control connection
    int ctlState = 0;               // 0 idle, 1 connecting, 2 await OK, 3 ready
    std::vector<u8> ctlBuf;
    u32 ctlRetryAt = 0;

    struct RelayAccept             // host: one dial-out per JOIN ticket
    {
        SOCKET s = INVALID_SOCKET;
        int state = 0;             // 1 connecting, 2 await OK
        u32 ticket = 0;
        u32 startedAt = 0;
        std::vector<u8> buf;
    };
    RelayAccept racc[7];

    SOCKET joinSock = INVALID_SOCKET;  // joiner handshake socket
    int joinState = 0;              // 0 idle, 1 connecting, 2 await OK, 3 linked
    std::vector<u8> joinBuf;
    u32 joinRetryAt = 0, joinStartedAt = 0;

    void setRelayStatus(const char* s)
    {
        strncpy(relayStatus, s, sizeof(relayStatus) - 1);
        relayStatus[sizeof(relayStatus) - 1] = 0;
    }

    void setRoomCode(const char* code)
    {
        int n = 0;
        for (const char* c = code; *c && n < 7; c++)
        {
            char ch = *c;
            if (ch >= 'a' && ch <= 'z') ch -= 32;
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') continue;
            roomCode[n++] = ch;
        }
        roomCode[n] = 0;
    }

    // "host[:port]" -> relayAddr. Blocking DNS: call from the UI or env init only, never per frame.
    bool resolveRelay(const char* spec)
    {
        char hostpart[160];
        int port = MP_RELAY_PORT;
        strncpy(hostpart, spec ? spec : "", sizeof(hostpart) - 1);
        hostpart[sizeof(hostpart) - 1] = 0;
        if (char* c = strrchr(hostpart, ':'))
        {
            *c = 0;
            int p = atoi(c + 1);
            if (p > 0 && p < 65536) port = p;
        }
        if (!hostpart[0]) return false;
        addrinfo hints; memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = NULL;
        if (getaddrinfo(hostpart, NULL, &hints, &res) != 0 || !res) return false;
        relayAddr = *(sockaddr_in*)res->ai_addr;
        relayAddr.sin_port = htons((u_short)port);
        freeaddrinfo(res);
        strncpy(relayDisp, spec, sizeof(relayDisp) - 1);
        relayDisp[sizeof(relayDisp) - 1] = 0;
        return true;
    }

    bool startHostOnline(const char* server)
    {
        if (!resolveRelay(server)) return false;
        mode = 1; onlineMode = 1; password[0] = 0;
        relayFatal = false; roomCode[0] = 0;
        ctlState = 0; ctlRetryAt = 0; ctlBuf.clear();
        setRelayStatus("contacting relay...");
        printf("[BR] online host via relay %s\n", relayDisp); fflush(stdout);
        return true;
    }

    bool startJoinOnline(const char* server, const char* code)
    {
        if (!resolveRelay(server)) return false;
        mode = 2; onlineMode = 2; password[0] = 0; authFail = 0;
        relayFatal = false; roomCode[0] = 0;
        if (code && code[0]) setRoomCode(code);
        joinState = 0; joinRetryAt = 0; joinBuf.clear();
        connecting = false;
        for (int i = 0; i < 7; i++) dropPeer(i);
        setRelayStatus(roomCode[0] ? "connecting..." : "waiting for room code...");
        printf("[BR] online join via relay %s code=%s\n", relayDisp,
            roomCode[0] ? roomCode : "(from file)");
        fflush(stdout);
        return true;
    }

    void relayShutdown()
    {
        if (ctlSock != INVALID_SOCKET) { closesocket(ctlSock); ctlSock = INVALID_SOCKET; }
        for (int i = 0; i < 7; i++) relayAccDrop(racc[i]);
        if (joinSock != INVALID_SOCKET) { closesocket(joinSock); joinSock = INVALID_SOCKET; }
        ctlState = 0; joinState = 0;
        ctlBuf.clear(); joinBuf.clear();
        onlineMode = 0; roomCode[0] = 0; relayStatus[0] = 0; relayFatal = false;
    }

    // Read one line from the relay: 1 = line, 0 = none yet, -1 = dead. Bytes left in buf are game data: keep them.
    static int relayReadLine(SOCKET s, std::vector<u8>& buf, char* out, int outMax)
    {
        // Deliver a buffered line before reporting the socket dead (the relay sends ERR and closes together).
        bool dead = false;
        char tmp[4096];
        for (;;)
        {
            int r = ::recv(s, tmp, sizeof(tmp), 0);
            if (r > 0) { buf.insert(buf.end(), tmp, tmp + r); if (buf.size() > 65536) return -1; }
            else if (r == 0) { dead = true; break; }
            else
            {
                if (WSAGetLastError() != WSAEWOULDBLOCK) dead = true;
                break;
            }
        }
        for (size_t i = 0; i < buf.size(); i++)
        {
            if (buf[i] != '\n') continue;
            size_t n = i;
            if (n && buf[n - 1] == '\r') n--;
            if ((int)n > outMax - 1) n = (size_t)(outMax - 1);
            memcpy(out, buf.data(), n); out[n] = 0;
            buf.erase(buf.begin(), buf.begin() + i + 1);
            return 1;              // dead-but-line-buffered: line first; the
        }                          // next call reports the dead socket
        return dead ? -1 : 0;
    }

    SOCKET relayDial()
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;
        setNonBlock(s);
        int r = ::connect(s, (sockaddr*)&relayAddr, sizeof(relayAddr));
        if (r == 0 || WSAGetLastError() == WSAEWOULDBLOCK) return s;
        closesocket(s);
        return INVALID_SOCKET;
    }

    static int connPoll(SOCKET s)   // -1 failed, 0 still connecting, 1 writable
    {
        fd_set wr, ex; FD_ZERO(&wr); FD_ZERO(&ex);
        FD_SET(s, &wr); FD_SET(s, &ex);
        timeval tv = { 0, 0 };
        int r = select(0, NULL, &wr, &ex, &tv);
        if (r <= 0) return 0;
        if (FD_ISSET(s, &ex)) return -1;
        return FD_ISSET(s, &wr) ? 1 : 0;
    }

    static bool sendLine(SOCKET s, const char* text)
    {
        char line[224];
        int n = _snprintf(line, sizeof(line) - 1, "%s\n", text);
        if (n <= 0) return false;
        return ::send(s, line, n, 0) == n;   // tiny writes; partial = failure
    }

    void relayAccDrop(RelayAccept& a)
    {
        if (a.s != INVALID_SOCKET) closesocket(a.s);
        a.s = INVALID_SOCKET; a.state = 0; a.ticket = 0; a.buf.clear();
    }

    void relayCtlDrop(u32 frame, const char* why)
    {
        if (ctlSock != INVALID_SOCKET) closesocket(ctlSock);
        ctlSock = INVALID_SOCKET; ctlState = 0; ctlBuf.clear();
        for (int i = 0; i < 7; i++) relayAccDrop(racc[i]);   // dead room's tickets
        roomCode[0] = 0;                 // a reconnect gets a NEW code
        ctlRetryAt = frame + 600;        // ~10 s
        setRelayStatus(why);
        printf("[BR] relay ctl: %s\n", why); fflush(stdout);
    }

    void relayHostLine(u32 frame, const char* line)
    {
        if (!strncmp(line, "OK ", 3))
        {
            setRoomCode(line + 3);
            ctlState = 3;
            char st[96];
            _snprintf(st, sizeof(st), "room code %s - share it", roomCode);
            setRelayStatus(st);
            printf("[BR] relay room code: %s\n", roomCode); fflush(stdout);
        }
        else if (!strncmp(line, "JOIN ", 5))
        {
            u32 ticket = (u32)atoi(line + 5);
            int used = 0;
            for (int k = 0; k < 7; k++)
                if (peers[k].up || peers[k].s != INVALID_SOCKET || racc[k].s != INVALID_SOCKET) used++;
            if (used >= 7)   // 7 joiner slots = 8-player rooms
            {
                printf("[BR] relay: no free slot, ignoring ticket %u\n", ticket);
                return;                  // ticket expires at the relay
            }
            for (int k = 0; k < 7; k++)
            {
                if (racc[k].s != INVALID_SOCKET) continue;
                racc[k].s = relayDial();
                if (racc[k].s == INVALID_SOCKET) return;
                racc[k].state = 1; racc[k].ticket = ticket;
                racc[k].startedAt = frame; racc[k].buf.clear();
                return;
            }
        }
        else if (!strcmp(line, "PING"))
        {
            sendLine(ctlSock, "PONG");
        }
        else if (!strncmp(line, "ERR ", 4))
        {
            char st[96];
            _snprintf(st, sizeof(st), "relay refused: %s", line + 4);
            setRelayStatus(st);
            printf("[BR] relay host error: %s\n", line); fflush(stdout);
            bool terminal = !strncmp(line + 4, "BADREQ", 6);
            if (ctlSock != INVALID_SOCKET) closesocket(ctlSock);
            ctlSock = INVALID_SOCKET; ctlState = 0; ctlBuf.clear(); roomCode[0] = 0;
            if (terminal) relayFatal = true;
            else ctlRetryAt = frame + 3600;   // FULL/RATE: back off ~60 s
        }
    }

    void relayHostTick(u32 frame)
    {
        if (ctlState == 0)
        {
            if (!relayFatal && frame >= ctlRetryAt)
            {
                ctlSock = relayDial();
                if (ctlSock == INVALID_SOCKET)
                {
                    ctlRetryAt = frame + 600;
                    setRelayStatus("relay unreachable, retrying...");
                }
                else ctlState = 1;
            }
        }
        else if (ctlState == 1)
        {
            int r = connPoll(ctlSock);
            if (r < 0) relayCtlDrop(frame, "relay unreachable, retrying...");
            else if (r > 0)
            {
                char hello[224];
                _snprintf(hello, sizeof(hello), "PMRELAY1 HOST %d %s",
                    (int)MP_WIRE_VER, myName[0] ? myName : "Player");
                if (sendLine(ctlSock, hello)) ctlState = 2;
                else relayCtlDrop(frame, "relay connection failed, retrying...");
            }
        }
        else
        {
            char line[256];
            int r = 0;
            while (ctlSock != INVALID_SOCKET
                && (r = relayReadLine(ctlSock, ctlBuf, line, sizeof(line))) > 0)
                relayHostLine(frame, line);
            if (ctlSock != INVALID_SOCKET && r < 0)
                relayCtlDrop(frame, "relay connection lost, retrying...");
        }

        // pending dial-out accepts (one per JOIN ticket)
        for (int i = 0; i < 7; i++)
        {
            RelayAccept& a = racc[i];
            if (a.s == INVALID_SOCKET) continue;
            if (frame - a.startedAt > 1200) { relayAccDrop(a); continue; }   // 20 s guard
            if (a.state == 1)
            {
                int r = connPoll(a.s);
                if (r < 0) { relayAccDrop(a); continue; }
                if (r > 0)
                {
                    char hello[64];
                    _snprintf(hello, sizeof(hello), "PMRELAY1 ACCEPT %s %u", roomCode, a.ticket);
                    if (sendLine(a.s, hello)) a.state = 2;
                    else { relayAccDrop(a); continue; }
                }
            }
            else if (a.state == 2)
            {
                char line[256];
                int r = relayReadLine(a.s, a.buf, line, sizeof(line));
                if (r < 0) { relayAccDrop(a); continue; }
                if (r == 0) continue;
                if (!strcmp(line, "OK"))
                {
                    int slot = -1;
                    for (int k = 0; k < 7; k++)
                        if (!peers[k].up && peers[k].s == INVALID_SOCKET) { slot = k; break; }
                    if (slot < 0) { relayAccDrop(a); continue; }
                    // install like an accepted LAN client; leftover bytes are the start of the game stream
                    MpPeer& p = peers[slot];
                    p.s = a.s; p.up = true;
                    p.rx.assign(a.buf.begin(), a.buf.end());
                    p.tx.clear();
                    freshPeer = true;
                    u8 ctl[4] = { 2, 0, 0xFF, (u8)(2 + slot) };
                    p.tx.insert(p.tx.end(), ctl, ctl + 4);
                    printf("[BR] relay peer spliced -> role %d\n", 2 + slot); fflush(stdout);
                    a.s = INVALID_SOCKET; a.state = 0; a.buf.clear();
                }
                else
                {
                    printf("[BR] relay accept refused: %s\n", line); fflush(stdout);
                    relayAccDrop(a);
                }
            }
        }
    }

    void relayJoinDrop(u32 frame, u32 backoff, const char* why)
    {
        if (joinSock != INVALID_SOCKET) closesocket(joinSock);
        joinSock = INVALID_SOCKET; joinBuf.clear();
        joinState = 0; joinRetryAt = frame + backoff;
        setRelayStatus(why);
    }

    void relayJoinTick(u32 frame)
    {
        if (relayFatal || !roomCode[0]) return;

        if (joinState == 3)
        {
            if (!peers[0].up)      // spliced link died: re-join through the relay
            {
                joinState = 0;
                joinRetryAt = frame + 600;
                setRelayStatus("connection lost, rejoining...");
            }
            return;
        }

        if (joinState == 0)
        {
            if (frame < joinRetryAt) return;
            joinSock = relayDial();
            if (joinSock == INVALID_SOCKET)
            {
                joinRetryAt = frame + 600;
                setRelayStatus("relay unreachable, retrying...");
                return;
            }
            joinBuf.clear();
            joinState = 1;
            joinStartedAt = frame;
            setRelayStatus("connecting...");
        }
        else if (joinState == 1)
        {
            int r = connPoll(joinSock);
            if (r < 0) { relayJoinDrop(frame, 600, "relay unreachable, retrying..."); return; }
            if (r > 0)
            {
                char hello[224];
                _snprintf(hello, sizeof(hello), "PMRELAY1 JOIN %s %d %s",
                    roomCode, (int)MP_WIRE_VER, myName[0] ? myName : "Player");
                if (sendLine(joinSock, hello)) { joinState = 2; setRelayStatus("waiting for host..."); }
                else relayJoinDrop(frame, 600, "relay connection failed, retrying...");
            }
            else if (frame - joinStartedAt > 1200)
                relayJoinDrop(frame, 600, "relay connect timeout, retrying...");
        }
        else if (joinState == 2)
        {
            char line[256];
            int r = relayReadLine(joinSock, joinBuf, line, sizeof(line));
            if (r < 0) { relayJoinDrop(frame, 600, "relay connection lost, retrying..."); return; }
            if (r == 0)
            {
                // the relay answers within its 15 s ticket window; 40 s = dead
                if (frame - joinStartedAt > 2400)
                    relayJoinDrop(frame, 600, "no relay answer, retrying...");
                return;
            }
            if (!strcmp(line, "OK"))
            {
                MpPeer& h = peers[0];
                h.s = joinSock; h.up = true;
                h.rx.assign(joinBuf.begin(), joinBuf.end());   // leftover = game bytes
                h.tx.clear();
                joinSock = INVALID_SOCKET; joinBuf.clear();
                joinState = 3;
                connecting = false;
                freshPeer = true;
                setRelayStatus("connected");
                printf("[BR] connected via relay (room %s)\n", roomCode); fflush(stdout);
            }
            else if (!strncmp(line, "ERR ", 4))
            {
                const char* e = line + 4;
                bool retry = !strncmp(e, "TIMEOUT", 7) || !strncmp(e, "CLOSED", 6)
                          || !strncmp(e, "RATE", 4);
                char st[96];
                if (!strncmp(e, "NOROOM", 6))
                    _snprintf(st, sizeof(st), "room %s not found - check the code", roomCode);
                else if (!strncmp(e, "VERSION", 7))
                    _snprintf(st, sizeof(st), "version mismatch with the host (%s)", e);
                else if (!strncmp(e, "FULL", 4))
                    _snprintf(st, sizeof(st), "room %s is full", roomCode);
                else
                    _snprintf(st, sizeof(st), "relay refused: %s", e);
                printf("[BR] relay join error: %s\n", line); fflush(stdout);
                relayJoinDrop(frame, retry ? 600 : 0, st);
                if (!retry) relayFatal = true;
            }
        }
    }

    void relayTick(u32 frame)
    {
        if (mode == 1) relayHostTick(frame);
        else if (mode == 2) relayJoinTick(frame);
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
        p.authed = true;
        p.rx.clear();
        p.tx.clear();
        if (mode == 2) connecting = false;
    }

    void tick(u32 frame)
    {
        if (mode == 0) return;

        if (onlineMode) relayTick(frame);   // relay handshakes + dial-out accepts

        if (mode == 1 && listener != INVALID_SOCKET)
        {
            // slot i is role 2+i, so a rejoining player gets its old role back
            for (int i = 0; i < 7; i++)
            {
                if (peers[i].up)
                {
                    // a password host gives a joiner 5 s to send it
                    if (!peers[i].authed && GetTickCount() - peers[i].upAt > 5000) rejectPeer(i, 2);
                    continue;
                }
                sockaddr_in from; int fl = sizeof(from);
                SOCKET s = accept(listener, (sockaddr*)&from, &fl);
                if (s == INVALID_SOCKET) break;
                if (ipBlocked(from.sin_addr.s_addr)) { closesocket(s); continue; }
                setNonBlock(s);
                peers[i].s = s; peers[i].up = true;
                peers[i].ip = from.sin_addr.s_addr; peers[i].upAt = GetTickCount();
                peers[i].authed = !password[0];
                if (!peers[i].authed) { printf("[BR] peer %d connected, waiting for password\n", i); continue; }
                freshPeer = true;
                u8 ctl[4] = { 2, 0, 0xFF, (u8)(2 + i) };   // [len=2][0xFF][role]
                peers[i].tx.insert(peers[i].tx.end(), ctl, ctl + 4);
                printf("[BR] peer accepted -> role %d\n", 2 + i);
            }
        }
        else if (mode == 2 && !onlineMode && !peers[0].up && !authFail)   // LAN/direct join only
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
                    sendPassword();
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
                if (r == 0) { h.up = true; sendPassword(); printf("[BR] connected to %s\n", joinIP); }
                else if (WSAGetLastError() == WSAEWOULDBLOCK) connecting = true;
                else { dropPeer(0); retryAt = frame + 120; }
            }
        }

        for (int i = 0; i < 7; i++) { flush(i); pumpRecv(i); }
    }

    void enqueue(int i, const u8* p, u32 n)
    {
        MpPeer& pr = peers[i];
        if (!pr.up || !pr.authed || n == 0 || n > MP_MAX_FRAME) return;
        if (pr.tx.size() > 512 * 1024) return;
        u8 hdr[2] = { (u8)(n & 0xFF), (u8)(n >> 8) };
        pr.tx.insert(pr.tx.end(), hdr, hdr + 2);
        pr.tx.insert(pr.tx.end(), p, p + n);
        flush(i);
    }

    void sendAll(const u8* p, u32 n)
    {
        for (int i = 0; i < 7; i++) enqueue(i, p, n);
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
            else if (r == 0)
            {
                // a refusal and the close arrive together: read the reason before dropping
                if (mode == 2 && i == 0 && p.rx.size() >= 4 && p.rx[0] == 2 && p.rx[1] == 0 && p.rx[2] == 0xFA)
                    authFail = (p.rx[3] == 2) ? 2 : 1;
                dropPeer(i); printf("[BR] peer %d closed\n", i); return;
            }
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
        for (int i = 0; i < 7; i++) dropPeer(i);
        if (listener != INVALID_SOCKET) { closesocket(listener); listener = INVALID_SOCKET; }
        relayShutdown();
        mode = 0;
    }
};

MpNet gNet;

// Bridge pump state
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

    // roleSeenAt = lobby presence (roster, beacon); gameSeenAt = in-game presence (what the ROM sees).
    u32 roleSeenAt[9] = {};
    u32 gameSeenAt[9] = {};

    u8 MaskOf(const u32* seen, int myRole) const
    {
        u8 m = 0;
        for (int r = 1; r <= 8; r++)
            if (r != myRole && seen[r] != 0 && frame - seen[r] <= 180)
                m |= (u8)(1u << (r - 1));
        return m;
    }
    u8 FreshPeerMask(int myRole) const { return MaskOf(roleSeenAt, myRole); }
    u8 GamePeerMask(int myRole)  const { return MaskOf(gameSeenAt, myRole); }
};
BridgeSt gBr;

} // namespace

// ---------------------------------------------------------------------------

// Win32 lobby: Multiplayer menu, Host / Join dialogs, and the roster window.
namespace {
enum { MP_ID_HOST = 0xE100, MP_ID_JOIN, MP_ID_STOP, MP_ID_HOSTON, MP_ID_JOINON, MP_ID_RELAYCFG };
HMENU gMpMenu = NULL;
struct FoundHost { char ip[32]; char name[28]; u32 seen; };
FoundHost gFound[8]; int gFoundN = 0;
HWND gLobby = NULL;

void MpArm() { gBr.armed = true; printf("[BR] armed via menu: mode=%d\n", gNet.mode); fflush(stdout); }

void MpBrowsePoll()
{
    gNet.startBeaconRx();
    if (gNet.beaconRx == INVALID_SOCKET) return;
    for (int guard = 0; guard < 64; guard++) {   // bounded: a beacon flood must not stall the dialog
        u8 buf[64]; sockaddr_in from; int fl = sizeof(from);
        int r = recvfrom(gNet.beaconRx, (char*)buf, sizeof(buf), 0, (sockaddr*)&from, &fl);
        if (r < 0) { if (WSAGetLastError() == WSAEMSGSIZE) continue; break; }
        if (r < 8 || memcmp(buf, "PLATMP", 6) != 0) continue;
        char ip[32]; strcpy(ip, inet_ntoa(from.sin_addr));
        char nm[28]; memset(nm, 0, sizeof(nm)); memcpy(nm, buf + 8, (r - 8 < 24) ? (r - 8) : 24);
        mpCleanName(nm);
        int idx = -1;
        for (int i = 0; i < gFoundN; i++) if (!strcmp(gFound[i].ip, ip)) { idx = i; break; }
        if (idx < 0 && gFoundN < 8) idx = gFoundN++;
        if (idx < 0) {                            // list full: the stalest entry gives way
            idx = 0;
            for (int i = 1; i < gFoundN; i++) if (gFound[i].seen > gFound[idx].seen) idx = i;
            if (gFound[idx].seen == 0) idx = -1;
        }
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
        if (gNet.onlineMode == 1)
        {
            if (gNet.roomCode[0])
                _snprintf(st, sizeof(st), "Online - room code %s - share it with joiners", gNet.roomCode);
            else
                _snprintf(st, sizeof(st), "Online - %s",
                    gNet.relayStatus[0] ? gNet.relayStatus : "contacting relay...");
        }
        else if (gNet.onlineMode == 2)
            _snprintf(st, sizeof(st), "Online - room %s (%s)",
                gNet.roomCode[0] ? gNet.roomCode : "?",
                gNet.anyUp() ? "connected"
                             : (gNet.relayStatus[0] ? gNet.relayStatus : "connecting..."));
        else if (gNet.mode == 1) _snprintf(st, sizeof(st), "Hosting on port 7820%s - waiting for players",
            gNet.password[0] ? " (password set)" : "");
        else if (gNet.authFail) _snprintf(st, sizeof(st), "%s",
            gNet.authFail == 2 ? "This host needs a password - leave and rejoin with it"
                               : "Wrong password - leave and rejoin");
        else _snprintf(st, sizeof(st), "%s %s", gNet.anyUp() ? "Connected to" : "Connecting to", gNet.joinIP);
        SetDlgItemTextA(h, 200, st);
        HWND lb = GetDlgItem(h, 201);
        SendMessageA(lb, LB_RESETCONTENT, 0, 0);
        int me = gNet.myRole(); u8 mask = gBr.FreshPeerMask(me);
        for (int r = 1; r <= 8; r++) {
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
static char gDlgPass[32];   // kept for the session only, never saved
INT_PTR CALLBACK HostProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_INITDIALOG) { SetDlgItemTextA(h, 100, gNet.myName); SetDlgItemTextA(h, 105, gDlgPass); SetFocus(GetDlgItem(h, 100)); return FALSE; }
    if (m == WM_COMMAND) {
        if (LOWORD(w) == IDOK) {
            GetDlgItemTextA(h, 100, gDlgName, sizeof(gDlgName));
            GetDlgItemTextA(h, 105, gDlgPass, sizeof(gDlgPass));
            EndDialog(h, 1); return TRUE;
        }
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
        SetDlgItemTextA(h, 105, gDlgPass);
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
            GetDlgItemTextA(h, 105, gDlgPass, sizeof(gDlgPass));
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
    static BYTE buf[2048]; memset(buf, 0, sizeof(buf));
    BYTE* p = BeginDlg(buf, 6, 180, 92, L"Host LAN Game");
    AddItem(p, SS_LEFT, 8, 8, 160, 10, (WORD)-1, 0x0082, L"Your name:");
    AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 8, 22, 164, 12, 100, 0x0081, L"");
    AddItem(p, SS_LEFT, 8, 40, 164, 10, (WORD)-1, 0x0082, L"Password (optional, blank = open):");
    AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 8, 52, 164, 12, 105, 0x0081, L"");
    AddItem(p, WS_TABSTOP | BS_DEFPUSHBUTTON, 60, 72, 56, 14, IDOK, 0x0080, L"Host Game");
    AddItem(p, WS_TABSTOP | BS_PUSHBUTTON, 122, 72, 50, 14, IDCANCEL, 0x0080, L"Cancel");
    return DialogBoxIndirectParamA(GetModuleHandle(NULL), (LPCDLGTEMPLATEA)buf, parent, HostProc, 0) == 1;
}
bool ShowJoinDialog(HWND parent)
{
    static BYTE buf[2048]; memset(buf, 0, sizeof(buf));
    BYTE* p = BeginDlg(buf, 9, 200, 168, L"Join LAN Game");
    AddItem(p, SS_LEFT, 8, 8, 80, 10, (WORD)-1, 0x0082, L"Your name:");
    AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 88, 6, 104, 12, 100, 0x0081, L"");
    AddItem(p, SS_LEFT, 8, 24, 184, 10, (WORD)-1, 0x0082, L"LAN games found:");
    AddItem(p, WS_BORDER | WS_TABSTOP | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT, 8, 36, 184, 70, 101, 0x0083, L"");
    AddItem(p, SS_LEFT, 8, 110, 60, 10, (WORD)-1, 0x0082, L"or IP address:");
    AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 70, 108, 122, 12, 102, 0x0081, L"");
    AddItem(p, SS_LEFT, 8, 128, 60, 10, (WORD)-1, 0x0082, L"Password:");
    AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 70, 126, 122, 12, 105, 0x0081, L"");
    AddItem(p, WS_TABSTOP | BS_DEFPUSHBUTTON, 74, 148, 50, 14, IDOK, 0x0080, L"Join");
    // Cancel shares the row via IDCANCEL implicit (Esc) — add explicit:
    return DialogBoxIndirectParamA(GetModuleHandle(NULL), (LPCDLGTEMPLATEA)buf, parent, JoinProc, 0) == 1;
}

// Online dialogs. The relay field shows only when "Custom Relay Server" is checked.
static char gDlgRelay[160];
static char gDlgCode[16];
static bool gShowRelayField = false;
static bool gShowRelayLoaded = false;

void mpLoadShowRelay()
{
    if (gShowRelayLoaded) return;
    gShowRelayLoaded = true;
    gShowRelayField = GetPrivateProfileIntA("ProjectPM", "ShowRelayField", 0, IniName) != 0;
}

void mpLoadRelayPref()
{
    if (!gDlgRelay[0])
        GetPrivateProfileStringA("ProjectPM", "RelayServer", "", gDlgRelay, sizeof(gDlgRelay), IniName);
    if (!gDlgRelay[0])   // nothing saved yet: pre-fill the community relay
    {
        strncpy(gDlgRelay, MP_DEFAULT_RELAY, sizeof(gDlgRelay) - 1);
        gDlgRelay[sizeof(gDlgRelay) - 1] = 0;
    }
}
void mpSaveRelayPref(const char* v)
{
    // Save only a custom relay; storing the default would shadow future defaults.
    if (!strcmp(v, MP_DEFAULT_RELAY))
        WritePrivateProfileStringA("ProjectPM", "RelayServer", NULL, IniName);
    else
        WritePrivateProfileStringA("ProjectPM", "RelayServer", v, IniName);
}

INT_PTR CALLBACK HostOnlineProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_INITDIALOG)
    {
        SetDlgItemTextA(h, 100, gNet.myName);
        mpLoadRelayPref();
        if (GetDlgItem(h, 103)) SetDlgItemTextA(h, 103, gDlgRelay);
        SetFocus(GetDlgItem(h, 100));
        return FALSE;
    }
    if (m == WM_COMMAND)
    {
        if (LOWORD(w) == IDOK)
        {
            GetDlgItemTextA(h, 100, gDlgName, sizeof(gDlgName));
            if (GetDlgItem(h, 103))
            {
                GetDlgItemTextA(h, 103, gDlgRelay, sizeof(gDlgRelay));
                if (!gDlgRelay[0])
                {
                    MessageBoxA(h, "Enter a relay server address (ask your community, or run pm_relay.py on a server).",
                        "Host Online Game", MB_OK);
                    return TRUE;
                }
            }
            else mpLoadRelayPref();   // hidden field: saved custom value or the baked default
            EndDialog(h, 1); return TRUE;
        }
        if (LOWORD(w) == IDCANCEL) { EndDialog(h, 0); return TRUE; }
    }
    return FALSE;
}

INT_PTR CALLBACK JoinOnlineProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_INITDIALOG)
    {
        SetDlgItemTextA(h, 100, gNet.myName);
        mpLoadRelayPref();
        if (GetDlgItem(h, 103)) SetDlgItemTextA(h, 103, gDlgRelay);
        SetFocus(GetDlgItem(h, 100));
        return FALSE;
    }
    if (m == WM_COMMAND)
    {
        if (LOWORD(w) == IDOK)
        {
            GetDlgItemTextA(h, 100, gDlgName, sizeof(gDlgName));
            GetDlgItemTextA(h, 104, gDlgCode, sizeof(gDlgCode));
            if (GetDlgItem(h, 103))
            {
                GetDlgItemTextA(h, 103, gDlgRelay, sizeof(gDlgRelay));
                if (!gDlgRelay[0])
                {
                    MessageBoxA(h, "Enter a relay server address (the host can tell you which one they used).",
                        "Join Online Game", MB_OK);
                    return TRUE;
                }
            }
            else mpLoadRelayPref();   // hidden field: saved custom value or the baked default
            int cn = 0;
            for (const char* c = gDlgCode; *c; c++) if (*c != ' ') cn++;
            if (cn < 5)
            {
                MessageBoxA(h, "Enter the 5 character room code the host shared.",
                    "Join Online Game", MB_OK);
                return TRUE;
            }
            EndDialog(h, 1); return TRUE;
        }
        if (LOWORD(w) == IDCANCEL) { EndDialog(h, 0); return TRUE; }
    }
    return FALSE;
}

bool ShowHostOnlineDialog(HWND parent)
{
    mpLoadShowRelay();
    static BYTE buf[1280]; memset(buf, 0, sizeof(buf));
    if (gShowRelayField)
    {
        BYTE* p = BeginDlg(buf, 6, 200, 94, L"Host Online Game");
        AddItem(p, SS_LEFT, 8, 8, 184, 10, (WORD)-1, 0x0082, L"Your name:");
        AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 8, 20, 184, 12, 100, 0x0081, L"");
        AddItem(p, SS_LEFT, 8, 38, 184, 10, (WORD)-1, 0x0082, L"Relay server (host or host:port):");
        AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 8, 50, 184, 12, 103, 0x0081, L"");
        AddItem(p, WS_TABSTOP | BS_DEFPUSHBUTTON, 84, 72, 56, 14, IDOK, 0x0080, L"Host Game");
        AddItem(p, WS_TABSTOP | BS_PUSHBUTTON, 146, 72, 46, 14, IDCANCEL, 0x0080, L"Cancel");
    }
    else
    {
        BYTE* p = BeginDlg(buf, 4, 200, 62, L"Host Online Game");
        AddItem(p, SS_LEFT, 8, 8, 184, 10, (WORD)-1, 0x0082, L"Your name:");
        AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 8, 20, 184, 12, 100, 0x0081, L"");
        AddItem(p, WS_TABSTOP | BS_DEFPUSHBUTTON, 84, 40, 56, 14, IDOK, 0x0080, L"Host Game");
        AddItem(p, WS_TABSTOP | BS_PUSHBUTTON, 146, 40, 46, 14, IDCANCEL, 0x0080, L"Cancel");
    }
    return DialogBoxIndirectParamA(GetModuleHandle(NULL), (LPCDLGTEMPLATEA)buf, parent, HostOnlineProc, 0) == 1;
}

bool ShowJoinOnlineDialog(HWND parent)
{
    mpLoadShowRelay();
    static BYTE buf[1536]; memset(buf, 0, sizeof(buf));
    if (gShowRelayField)
    {
        BYTE* p = BeginDlg(buf, 8, 200, 124, L"Join Online Game");
        AddItem(p, SS_LEFT, 8, 8, 184, 10, (WORD)-1, 0x0082, L"Your name:");
        AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 8, 20, 184, 12, 100, 0x0081, L"");
        AddItem(p, SS_LEFT, 8, 38, 184, 10, (WORD)-1, 0x0082, L"Relay server (host or host:port):");
        AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 8, 50, 184, 12, 103, 0x0081, L"");
        AddItem(p, SS_LEFT, 8, 68, 90, 10, (WORD)-1, 0x0082, L"Room code:");
        AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL | ES_UPPERCASE, 8, 80, 70, 12, 104, 0x0081, L"");
        AddItem(p, WS_TABSTOP | BS_DEFPUSHBUTTON, 84, 102, 56, 14, IDOK, 0x0080, L"Join");
        AddItem(p, WS_TABSTOP | BS_PUSHBUTTON, 146, 102, 46, 14, IDCANCEL, 0x0080, L"Cancel");
    }
    else
    {
        BYTE* p = BeginDlg(buf, 6, 200, 92, L"Join Online Game");
        AddItem(p, SS_LEFT, 8, 8, 184, 10, (WORD)-1, 0x0082, L"Your name:");
        AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 8, 20, 184, 12, 100, 0x0081, L"");
        AddItem(p, SS_LEFT, 8, 38, 90, 10, (WORD)-1, 0x0082, L"Room code:");
        AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL | ES_UPPERCASE, 8, 50, 70, 12, 104, 0x0081, L"");
        AddItem(p, WS_TABSTOP | BS_DEFPUSHBUTTON, 84, 70, 56, 14, IDOK, 0x0080, L"Join");
        AddItem(p, WS_TABSTOP | BS_PUSHBUTTON, 146, 70, 46, 14, IDCANCEL, 0x0080, L"Cancel");
    }
    return DialogBoxIndirectParamA(GetModuleHandle(NULL), (LPCDLGTEMPLATEA)buf, parent, JoinOnlineProc, 0) == 1;
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
    AppendMenuA(gMpMenu, MF_STRING, MP_ID_HOSTON, "Host &Online Game...");
    AppendMenuA(gMpMenu, MF_STRING, MP_ID_JOINON, "Join O&nline Game...");
    AppendMenuA(gMpMenu, MF_STRING, MP_ID_RELAYCFG, "Custom &Relay Server");
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
    EnableMenuItem(gMpMenu, MP_ID_HOSTON, MF_BYCOMMAND | (gNet.mode ? MF_GRAYED : MF_ENABLED));
    EnableMenuItem(gMpMenu, MP_ID_JOINON, MF_BYCOMMAND | (gNet.mode ? MF_GRAYED : MF_ENABLED));
    EnableMenuItem(gMpMenu, MP_ID_STOP, MF_BYCOMMAND | (gNet.mode ? MF_ENABLED : MF_GRAYED));
    mpLoadShowRelay();
    CheckMenuItem(gMpMenu, MP_ID_RELAYCFG, MF_BYCOMMAND | (gShowRelayField ? MF_CHECKED : MF_UNCHECKED));
}

bool MpBridge_HandleCommand(unsigned int id)
{
    HWND w = GetActiveWindow();
    if (id == MP_ID_HOST) {
        if (ShowHostDialog(w)) { gNet.setName(gDlgName); gNet.setPassword(gDlgPass); gNet.startHost(); MpArm(); OpenLobby(w); }
        return true;
    }
    if (id == MP_ID_JOIN) {
        gFoundN = 0;
        if (ShowJoinDialog(w) && gNet.joinIP[0]) { gNet.setName(gDlgName); gNet.setPassword(gDlgPass); gNet.joinTo(gNet.joinIP); MpArm(); OpenLobby(w); }
        return true;
    }
    if (id == MP_ID_HOSTON) {
        if (ShowHostOnlineDialog(w)) {
            gNet.setName(gDlgName);
            if (gNet.startHostOnline(gDlgRelay)) { mpSaveRelayPref(gDlgRelay); MpArm(); OpenLobby(w); }
            else MessageBoxA(w, "Could not resolve the relay server address.",
                "Host Online Game", MB_OK | MB_ICONERROR);
        }
        return true;
    }
    if (id == MP_ID_JOINON) {
        if (ShowJoinOnlineDialog(w)) {
            gNet.setName(gDlgName);
            if (gNet.startJoinOnline(gDlgRelay, gDlgCode)) { mpSaveRelayPref(gDlgRelay); MpArm(); OpenLobby(w); }
            else MessageBoxA(w, "Could not resolve the relay server address.",
                "Join Online Game", MB_OK | MB_ICONERROR);
        }
        return true;
    }
    if (id == MP_ID_RELAYCFG) {
        mpLoadShowRelay();
        gShowRelayField = !gShowRelayField;
        WritePrivateProfileStringA("ProjectPM", "ShowRelayField",
            gShowRelayField ? "1" : "0", IniName);
        return true;
    }
    if (id == MP_ID_STOP) {
        if (gLobby) { DestroyWindow(gLobby); gLobby = NULL; }
        gNet.shutdownAll(); gNet.mode = 0; gBr.armed = false; return true;
    }
    return false;
}

void MpBridge_Shutdown()
{
    gNet.shutdownAll();
}

// Debug tripwire: logs writes into the SDK alarm structures that come from outside the SDK code.
bool gMpWatchArmed = false;
struct MpWatchRange { u32 lo, hi; };
static MpWatchRange sWatchRanges[20];
static int  sWatchCount = 0;
static u32  sWatchQueueAddr = 0;
static u32  sWatchNodes[16];
static int  sWatchNodeCount = 0;
static u32  sNodeSnapHandler[16];
static u32  sWatchHits = 0;
static FILE* sWatchLogF = NULL;

static void MpWatchLog(const char* fmt, ...)
{
    if (!sWatchLogF) sWatchLogF = fopen("desmume_alarmwatch.txt", "a");
    if (!sWatchLogF) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(sWatchLogF, fmt, ap);
    va_end(ap);
    fflush(sWatchLogF);
}

static int sWatchRole = 0;
static int sTableRange = -1;   // extra range from mp_table_watch.txt: log ALL writers

void MpWatch_OnWrite(unsigned int address, int size, unsigned int value)
{
    for (int i = 0; i < sWatchCount; i++)
    {
        if (address >= sWatchRanges[i].lo && address < sWatchRanges[i].hi)
        {
            u32 pc9 = NDS_ARM9.instruct_adr;
            // SDK code may write here; only foreign writers matter (the table watch logs everyone).
            if (i != sTableRange && pc9 >= 0x020CF000 && pc9 < 0x020DF000) return;
            // one log line per (PC, 16-byte bucket)
            {
                static u32 sSeenPC[192], sSeenAddr[192];
                static int sSeenN = 0;
                u32 bucket = address & ~0xFu;
                for (int k = 0; k < sSeenN; k++)
                    if (sSeenPC[k] == pc9 && sSeenAddr[k] == bucket) return;
                if (sSeenN < 192) { sSeenPC[sSeenN] = pc9; sSeenAddr[sSeenN] = bucket; sSeenN++; }
            }
            if (sWatchHits++ > 1500) return;   // absolute cap
            MpWatchLog("WRITE role=%d f=%u addr=%08X val=%08X size=%d PC9=%08X LR9=%08X CPSR9=%08X PC7=%08X\n",
                sWatchRole, gBr.frame, address, value, size,
                pc9, NDS_ARM9.R[14], NDS_ARM9.CPSR.val, NDS_ARM7.instruct_adr);
            return;
        }
    }
}

void MpBridge_Pump()
{
    if (!gBr.armed) return;
    gBr.frame++;

    gNet.tick(gBr.frame);

    // A peer link just came up: clear the send caches so party/pkt are resent.
    if (gNet.freshPeer)
    {
        gNet.freshPeer = false;
        gBr.lastParty.clear();
        gBr.lastPkt.clear();
    }

    // Find the ROM's discovery block. Must not gate the transport: the lobby connects at the title screen.
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

    // LAN beacon: LAN hosting only (an online room is not joinable over LAN).
    if (gNet.mode == 1 && !gNet.onlineMode && (gBr.frame - gNet.lastBeacon) >= 60) {
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

    // No early return while the ROM is not up: the lobby still needs the receive loop below.
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
        for (int pi = 0; pi < 7; pi++)
        while ((n = gNet.recvFrame(pi, rx, sizeof(rx))) > 0)
        {
            gBr.dbgRx++;
            if (!gNet.peers[pi].authed) { gNet.checkPassword(pi, rx, n); continue; }
            if (rx[0] == 0xFB) continue;
            if (n == 2 && rx[0] == 0xFA)
            {
                // the host refused us: stop redialling and let the lobby say why
                if (gNet.mode == 2 && pi == 0) { gNet.authFail = (rx[1] == 2) ? 2 : 1; gNet.dropPeer(0); }
                continue;
            }
            if (n == 2 && rx[0] == 0xFF)
            {
                // role assignment: only a joiner takes it, and only from the host link
                if (gNet.mode == 2 && pi == 0 && rx[1] >= 2 && rx[1] <= 8)
                {
                    gNet.assignedRole = rx[1];
                    gNet.sendName(gNet.myRole());
                }
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
                if (r2 >= 1 && r2 <= 8 && nl <= 23 && (u32)n >= (u32)(5 + nl)
                    && gNet.roleAllowed(pi, r2)) {
                    memcpy(gNet.rname[r2], rx + 5, nl); gNet.rname[r2][nl] = 0; gNet.rping[r2] = png;
                    mpCleanName(gNet.rname[r2]);
                    gBr.roleSeenAt[r2] = gBr.frame;
                    if (myRole == 1) for (int pj = 0; pj < 7; pj++) if (pj != pi) gNet.enqueue(pj, rx, n);
                }
                continue;
            }
            if (n < 4) continue;
            int tag = rx[0], r = rx[1];
            u32 sz = (u32)(rx[2] | (rx[3] << 8));
            if (r < 1 || r > 8 || r == myRole) continue;
            if (!gNet.roleAllowed(pi, r)) continue;
            if (n < 4 + sz) continue;

            // Host relay: forward each client's bundle to the other clients.
            if (myRole == 1)
                for (int pj = 0; pj < 7; pj++)
                    if (pj != pi) gNet.enqueue(pj, rx, n);

            gBr.roleSeenAt[r] = gBr.frame;
            if (tag >= 1 && tag <= 3)
            {
                // Peer newly in game: resend our party/pkt.
                bool wasFresh = gBr.gameSeenAt[r] != 0 && gBr.frame - gBr.gameSeenAt[r] <= 180;
                if (!wasFresh)
                {
                    gBr.lastParty.clear();
                    gBr.lastPkt.clear();
                }
                gBr.gameSeenAt[r] = gBr.frame;
            }

            // Apply whenever the ROM is up. The pairwise import only takes the chosen partner (pairRole).
            if (romUp && tag == 1 && sz == gBr.blkSize && n >= 4 + sz + 48)
            {
                u8 pairRole = apRd8(gBr.owExp + 0x18);
                // With 2+ game peers the pairwise import is strict: only the chosen partner, never "first come".
                int gamePeers = 0;
                for (int gb = 1; gb <= 8; gb++)
                    if (gb != myRole && gBr.roleSeenAt[gb] != 0
                        && gBr.frame - gBr.roleSeenAt[gb] <= 300
                        && gBr.gameSeenAt[gb] != 0) gamePeers++;
                bool strict = (gamePeers >= 2);
                rx[4 + 0x12] = (u8)r;   // stamp the sender's role into the block
                if ((pairRole == 0 && !strict) || r == (int)pairRole)
                    memcpy(apPtr(gBr.importBlk), rx + 4, sz);
                if (gBr.blkN) memcpy(apPtr(gBr.blkN + (r-1)*sz), rx + 4, sz);
                memcpy(apPtr(gBr.owImp + (r-1)*48), rx + 4 + sz, 48);
            }
            else if (romUp && tag == 2 && sz == gBr.partySize)
            {
                u8 pairRole = apRd8(gBr.owExp + 0x18);
                int gamePeers = 0;
                for (int gb = 1; gb <= 8; gb++)
                    if (gb != myRole && gBr.roleSeenAt[gb] != 0
                        && gBr.frame - gBr.roleSeenAt[gb] <= 300
                        && gBr.gameSeenAt[gb] != 0) gamePeers++;
                bool strict = (gamePeers >= 2);
                if ((pairRole == 0 && !strict) || r == (int)pairRole)
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

    // pairRole changed to a real role: replay that role's cached block and party. A change to 0 is ignored (it flaps).
    if (romUp && gBr.owExp && gBr.importBlk)
    {
        static u8 sLastPairRole = 0xFF;
        u8 pr = apRd8(gBr.owExp + 0x18);
        if (pr != sLastPairRole)
        {
            sLastPairRole = pr;
            if (pr >= 1 && pr <= 8)
            {
                if (gBr.blkN)
                    memcpy(apPtr(gBr.importBlk), apPtr(gBr.blkN + (pr-1)*gBr.blkSize), gBr.blkSize);
                if (gBr.partyN && gBr.partyImp)
                    memcpy(apPtr(gBr.partyImp), apPtr(gBr.partyN + (pr-1)*gBr.partySize), gBr.partySize);
            }
        }
    }
    if (romUp && gBr.exportBlk && gBr.importBlk)
    {
        static u8 sLastOwnInBattle = 0;
        u8 ib = apRd8(gBr.exportBlk + 0x10);
        if (!ib && sLastOwnInBattle)
            apWr32(gBr.importBlk, 0);   // battle over: purge partner-block ghost
        sLastOwnInBattle = ib;
    }

    if (inGame)
    {
        // Game peer mask, not the lobby one: "connected" means the peer is sending game data.
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

    // Crash catcher: overworld frame counter frozen during a session, so dump the ARM9 registers.
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

    // ---- alarm tripwire maintenance: learn queue + armed structs, verify ----
    if (romUp && gBr.ctl)
    {
        // ctl+16 points into the OS alarm statics; watch the area and find the queue head in it.
        u32 w = apRd32(gBr.ctl + 16);
        if (w >= 0x02000000 && w < 0x02400000)
        {
            u32 lo = (w - 0x10) & ~3u;
            if (sWatchQueueAddr != w)
            {
                sWatchQueueAddr = w;
                sWatchCount = 0;
                sWatchNodeCount = 0;
                sWatchHits = 0;
                sWatchRole = myRole;
                sWatchRanges[sWatchCount].lo = lo;
                sWatchRanges[sWatchCount].hi = lo + 0x48;
                sWatchCount++;
                // Also watch the wider SDK statics band around it.
                sWatchRanges[sWatchCount].lo = (w > 0x02002600) ? (w - 0x2600) : 0x02000000;
                sWatchRanges[sWatchCount].hi = w + 0x2800;
                sWatchCount++;
                gMpWatchArmed = true;
                MpWatchLog("ARMED role=%d f=%u cluster=%08X..%08X band=%08X..%08X (lit=%08X)\n",
                    myRole, gBr.frame, lo, lo + 0x48,
                    sWatchRanges[1].lo, sWatchRanges[1].hi, w);
                // Optional extra watch range from mp_table_watch.txt ("addr len" in hex).
                {
                    FILE* tf = fopen("mp_table_watch.txt", "r");
                    if (tf) {
                        unsigned taddr = 0, tlen = 0;
                        if (fscanf(tf, "%x %x", &taddr, &tlen) == 2
                            && taddr >= 0x02000000u && taddr < 0x02400000u
                            && tlen > 0 && tlen <= 0x1000u && sWatchCount < 20) {
                            sTableRange = sWatchCount;
                            sWatchRanges[sWatchCount].lo = taddr;
                            sWatchRanges[sWatchCount].hi = taddr + tlen;
                            sWatchCount++;
                            MpWatchLog("TABLEWATCH role=%d %08X..%08X\n", myRole, taddr, taddr + tlen);
                        }
                        fclose(tf);
                    }
                }
            }
            // The queue head is a word here that points at a plausible OSAlarm.
            static u32 sResolvedHead = 0;
            if (!sResolvedHead)
            {
                for (u32 cand = lo; cand < lo + 0x48; cand += 4)
                {
                    u32 v = apRd32(cand);
                    if (v < 0x02000000 || v >= 0x02400000 || (v & 3)) continue;
                    u32 h = apRd32(v);                 // candidate node's handler
                    if (h >= 0x02000000 && h < 0x02400000)
                    {
                        sResolvedHead = cand;
                        MpWatchLog("QUEUE f=%u head=%08X (first node=%08X handler=%08X)\n",
                            gBr.frame, cand, v, h);
                        break;
                    }
                }
            }
            // Walk the queue; remember every armed alarm struct (sticky).
            u32 node = sResolvedHead ? apRd32(sResolvedHead) : 0;
            for (int g = 0; g < 8 && node; g++)
            {
                if (node < 0x02000000 || node >= 0x02400000 || (node & 3)) break;
                int ki = -1;
                for (int i = 0; i < sWatchNodeCount; i++)
                    if (sWatchNodes[i] == node) { ki = i; break; }
                if (ki < 0 && sWatchNodeCount < 16 && sWatchCount < 20)
                {
                    ki = sWatchNodeCount;
                    sWatchNodes[sWatchNodeCount++] = node;
                    sWatchRanges[sWatchCount].lo = node;
                    sWatchRanges[sWatchCount].hi = node + 0x2C;   // sizeof(OSAlarm)
                    sWatchCount++;
                    sNodeSnapHandler[ki] = apRd32(node);
                    MpWatchLog("NODE f=%u addr=%08X handler=%08X arg=%08X tag=%08X period=%08X%08X\n",
                        gBr.frame, node, apRd32(node), apRd32(node + 4), apRd32(node + 8),
                        apRd32(node + 0x20), apRd32(node + 0x1C));
                }
                node = apRd32(node + 0x18);   // OSAlarm.next
            }
            // A remembered alarm's handler must not change while we watch.
            for (int i = 0; i < sWatchNodeCount; i++)
            {
                u32 h = apRd32(sWatchNodes[i]);
                if (h != sNodeSnapHandler[i])
                {
                    MpWatchLog("CONTENT f=%u node=%08X handler %08X -> %08X period=%08X R15(9)=%08X\n",
                        gBr.frame, sWatchNodes[i], sNodeSnapHandler[i], h,
                        apRd32(sWatchNodes[i] + 0x1C), NDS_ARM9.instruct_adr);
                    sNodeSnapHandler[i] = h;
                }
            }
        }
    }
}
