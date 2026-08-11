# DeSmuME - Project PM fork

A fork of the [DeSmuME](https://desmume.org/) Nintendo DS emulator carrying the
embedded multiplayer bridge for **Project PM**, a co-op multiplayer romhack of
Pokémon Platinum.

Based on a DeSmuME 0.9.14 development snapshot.

## What's different from stock DeSmuME

- **Embedded multiplayer bridge** (`desmume/src/frontend/windows/mp_bridge.cpp`):
  a TCP host/join transport built into the emulator. One player hosts, up to
  three more join, and the bridge syncs the romhack's multiplayer mailboxes between instance.
- **Online play through a relay**: "Host Online Game" gets you a 5 character
  room code from a relay server; friends join with the code. No port
  forwarding, and players never see each other's IP address.
- **Wireless lobby UI**: a small in-emulator window showing connected players,
  names and ping while a session is up.

The sibling melonDS port of the same bridge lives at
[ComicartOlie/melonDS-Project-PM](https://github.com/ComicartOlie/melonDS-Project-PM) (branch
`platinum-mp`).

## Playing online (recommended: relay room codes)

Use **Host Online Game** in the Multiplayer menu: the relay server field
comes pre-set to the community relay, so just click through and the
emulator shows a 5 character room code. Share the code; everyone else uses
**Join Online Game** and enters the code. That's the whole setup:

- No port forwarding, no firewall rule, no router settings, for anyone.
- Works behind CGNAT.
- Players never see each other's IP address; every player connects out to
  the relay like connecting to any game server.

The relay server software is a small open source Python script
(`tools/relay/pm_relay.py` in the Project PM repo), so any community member
can run one on a cheap VPS and share its address.

## Hosting over the internet (direct, no relay)

The old direct way still works and has the lowest possible latency. One
player hosts ("Host LAN Game" in the Multiplayer menu); everyone else
joins with the host's IP. On the same LAN or a VPN (Hamachi, Radmin,
ZeroTier, Tailscale) this works with no setup. To host over the open
internet, three things must all be true on the **host's** side. Joiners
never need any of this:

1. **Router port forward**: forward **TCP 7820** to the host PC.
2. **Windows Firewall**: the router forwards the connection, but Windows
   still has to accept it. The first time you host, the emulator offers to
   add the firewall rule for you (one admin prompt, one time). Say yes.
3. **A real public IP**: if your router's WAN address (in its admin page)
   is different from what whatismyip.com shows, or starts with
   100.64-100.127, your ISP has you behind CGNAT and no amount of port
   forwarding will work. Use the relay instead (see above), or a VPN like
   Hamachi/ZeroTier, or have a friend with a real IP host.

## Building

Windows, Visual Studio 2022:

1. Open `desmume/src/frontend/windows/DeSmuME.sln`
2. Configuration **Release Fastbuild**, platform **x64**
3. Build. The exe lands in `desmume/src/frontend/windows/__bins/`

## Branch

All fork work is on **`platinum-mp`**.

## License

DeSmuME is licensed under the **GNU GPL v2**, and so is this fork. All credit for the emulator
itself goes to the DeSmuME team.
