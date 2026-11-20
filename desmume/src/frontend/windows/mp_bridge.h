// Mailbox bridge for the Pokémon Platinum multiplayer romhack.
// Syncs the ROM's multiplayer mailboxes over TCP (:7820) each frame; the emulated radio is never touched.
// Wire frame: [u16 len LE][tag u8][role u8][size u16 LE][payload]; tag 1 = block+ow, 2 = party, 3 = pkt.

#ifndef MP_BRIDGE_H
#define MP_BRIDGE_H

// Per-frame pump. Call right after NDS_exec returns, inside the run loop's lock.
void MpBridge_Pump();

// Close sockets. Call before WSACleanup.
void MpBridge_Shutdown();

// Win32 lobby UI hooks
struct HWND__; typedef struct HWND__* HWND;
struct HMENU__; typedef struct HMENU__* HMENU;
void MpBridge_InstallMenu(HWND mainWnd);          // append the Multiplayer menu
bool MpBridge_HandleCommand(unsigned int id);     // WM_COMMAND; true if ours
void MpBridge_OnInitPopup(HMENU menu);            // WM_INITMENUPOPUP


#endif
