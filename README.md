# DeSmuME — Project PM fork

A fork of the [DeSmuME](https://desmume.org/) Nintendo DS emulator carrying the
embedded multiplayer bridge for **Project PM**, a co-op multiplayer romhack of
Pokémon Platinum. This is the Windows build bundled with the mod; players don't
need anything from this repo unless they want to build the emulator themselves
or read how the netplay works.

Based on a DeSmuME 0.9.14 development snapshot. This repository's history
starts at that snapshot rather than at upstream's git history, so it is
published as a standalone repository instead of a GitHub fork.

## What's different from stock DeSmuME

- **Embedded multiplayer bridge** (`desmume/src/frontend/windows/mp_bridge.cpp`):
  a TCP host/join transport built into the emulator. One player hosts, up to
  three more join, and the bridge syncs the romhack's multiplayer mailboxes
  (positions, parties, battle state) between instances every frame — no Lua
  scripts, no external relay.
- **Wireless lobby UI**: a small in-emulator window showing connected players,
  names and ping while a session is up.
- **Strict pair routing** for 3–4 player sessions, so two co-op battles can run
  side by side against the same trainer without cross-talk.
- **Test harness** (environment-driven, used for the mod's automated testing):
  scripted boot/connect autopilot, role-aware live input, frame-accurate input
  record/replay, and an always-on crash catcher that dumps ARM9 state when the
  game wedges. Controlled through `MELONDS_AP*` environment variables (the
  names are historical — the bridge was first written for a melonDS fork and
  ported here). Unset, all of it is inert.

The sibling melonDS port of the same bridge lives at
[ComicartOlie/melonDS](https://github.com/ComicartOlie/melonDS) (branch
`platinum-mp`).

## Building

Windows, Visual Studio 2022:

1. Open `desmume/src/frontend/windows/DeSmuME.sln`
2. Configuration **Release Fastbuild**, platform **x64**
3. Build — the exe lands in `desmume/src/frontend/windows/__bins/`

## Branch

All fork work is on **`platinum-mp`**.

## License

DeSmuME is licensed under the **GNU GPL v2**, and so is this fork — this
repository exists to satisfy that license by providing the complete modified
source for the binaries distributed with the mod. All credit for the emulator
itself goes to the DeSmuME team.
