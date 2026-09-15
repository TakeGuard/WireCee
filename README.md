# WireCee

Personal firewall for Windows and Linux by TakeGuard.

It shows what every program on your machine is talking to, and lets you stop it.
Not a wrapper around Windows Firewall: the engine reads the real connection
tables itself, enforces its own rules through the Windows Filtering Platform,
and can filter DNS for the whole machine.

## What it does

- Live connections per application, with host names, state and byte counts
- Allow, block or ask per application. Ask refuses a new program until you decide
- Rules by address, port, protocol and direction, with lists of hundreds of
  addresses in one rule
- A built in rule blocking known malware C2 servers
- Data usage per day and per application, with a monthly limit and alerts
- DNS filtering with your own blocklist, and a guard so nothing can go around it
- Devices on your local network, with names you can set
- Alerts for hosts file changes, DNS server changes, proxy changes, incoming
  Remote Desktop and modified executables
- The window and the command line use the same engine, so they never disagree

## Install

Windows: grab the zip from Releases, unpack it anywhere, run `WireCee.exe`. It asks for
administrator rights. Without them it still monitors everything, but it cannot
block, filter DNS, or count bytes per application.

Everything it saves lives in `C:\ProgramData\TakeGuard\WireCee`: settings, daily
logs, usage history and the DNS blocklist.

Linux: grab the tar.gz, unpack it, run `sudo ./wirecee --open`. It needs
nftables for blocking and conntrack for UDP. Data lives in `/var/lib/wirecee`.

## Build

Needs Visual Studio Build Tools with the C++ workload.

The CEF binaries are too big for git, so get them first. Download the Windows
64-bit minimal distribution of CEF `107.0.1+g318ab17+chromium-107.0.5304.18`
from https://cef-builds.spotifycdn.com/index.html and copy:

- `Release/libcef.lib` and `Release/cef_sandbox.lib` to `third_party/cef/lib`
- the other files in `Release` and everything in `Resources` to
  `third_party/cef/runtime`

```
msbuild build\windows\WireCee.sln /p:Configuration=Release /p:Platform=x64
```

Output goes to `build\out\windows`, complete with the CEF runtime and the web
interface, so you can run it straight from there. To make a release zip:

```
powershell -ExecutionPolicy Bypass -File tools\package.ps1
```

On Linux `make -C build/linux` builds and `make -C build/linux dist` makes the
release tar.gz in `dist`.

The C2 list comes from the TweetFeed feed. `python tools/update-c2.py` refreshes
it, then rebuild.

## Command line

```
wirecee connections
wirecee apps --blocked
wirecee block chrome.exe
wirecee usage --days 30
wirecee devices
wirecee alerts
wirecee dns block ads.example.com
wirecee --status
wirecee --stop
```

`wirecee --help` lists the rest. Query commands do not need administrator rights.

## Layout

```
src/core        engine, HTTP API, CLI, DNS resolver. Portable
src/windows     Windows platform code, tray host, CEF window
src/linux       Linux platform code and daemon
src/web         the interface, plain html, css and js, no build step
third_party     civetweb and CEF
build/windows   Visual Studio solution
build/linux     Makefile and systemd unit
tools           packaging and the C2 list updater
tests           test scripts
docs            Linux notes
```

## Tests

```
powershell -ExecutionPolicy Bypass -File tests\cli-flow.ps1
powershell -ExecutionPolicy Bypass -File tests\settings-check.ps1
```

Both start their own engine on a scratch data directory, so they never touch
your saved settings. A few checks need administrator rights and say so when they
are skipped.

## Linux

Blocking uses nftables, DNS filtering rewrites `/etc/resolv.conf` and restores
it after. The interface opens in your browser. See [docs/LINUX.md](docs/LINUX.md).

## License

PolyForm Noncommercial 1.0.0. Use it, read it, change it, share it, just not
commercially. That restriction means it is source available rather than OSI open
source, which is deliberate.
