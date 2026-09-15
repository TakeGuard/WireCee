# WireCee on Linux

WireCee for Linux uses the same engine, HTTP API, command line and interface as
the Windows build. The operating system integration is replaced:

| Feature | Windows | Linux |
|---|---|---|
| Connections and owners | IP Helper API | `/proc/net/tcp`, `/proc/<pid>/fd` |
| Per connection bytes | TCP extended statistics | `sock_diag` (`tcp_info`) |
| UDP flows | Kernel ETW trace | conntrack accounting |
| Blocking | Windows Filtering Platform | nftables table `inet wirecee` |
| Application policy | WFP application id | cgroup v2 groups matched by nftables |
| DNS filtering | Adapter DNS settings | `/etc/resolv.conf` |
| Start automatically | Scheduled task | systemd service |
| Interface | Native window | Any browser |

## Requirements

Tested target: Kali Linux rolling.

```bash
sudo apt install build-essential linux-libc-dev nftables conntrack
```

cgroup v2 is required for application policies. Kali and every current
systemd distribution mount it at `/sys/fs/cgroup` by default.

## Build

```bash
make -C build/linux
make -C build/linux dist
```

The binary is written to `build/out/linux/wirecee`. `dist` packs it with the
interface into `dist/WireCee-<version>-linux-<arch>.tar.gz`. The binary finds
the interface in `app` next to it, in `src/web` in the source tree, or in
`/usr/share/wirecee/app` once installed.

## Run

Blocking, DNS filtering and UDP tracing require root. Monitoring works as a
normal user.

```bash
sudo ./build/out/linux/wirecee --open
```

`--open` launches your browser as the user who ran sudo. Without it, open the
address printed in the terminal. Stop the engine with Ctrl+C or:

```bash
sudo ./build/out/linux/wirecee --stop
```

## Install as a service

```bash
sudo make -C build/linux install
sudo wirecee --install-service
```

The service listens on port 30700 when it is free. Query commands work from
any user:

```bash
wirecee connections
wirecee apps
wirecee usage --days 30
wirecee dns
```

Remove it with `sudo wirecee --uninstall-service` and `sudo make -C build/linux uninstall`.

## Behavior and limitations

- **Application policies** move the processes of a blocked application into
  `/sys/fs/cgroup/wirecee-blocked`. WireCee rechecks running processes every two
  seconds, so a newly started blocked program can send traffic for up to that
  long. Ask behaves like Block until you choose.
- **DNS filtering** rewrites `/etc/resolv.conf` and restores it on stop. If
  NetworkManager or systemd-resolved rewrite the file while filtering is on,
  turn filtering off and on again. The original servers stay listed as
  fallbacks, so name resolution keeps working if WireCee stops unexpectedly.
  A backup is restored automatically on the next start.
- **Host names** in Connections appear while DNS filtering is on. The Windows
  build also reads them from the DNS client trace.
- **Terminating a connection** uses `ss -K`, which needs a kernel built with
  `CONFIG_INET_DIAG_DESTROY`.
- **Remote access alerts** watch inbound SSH on port 22.
- **Rule hit counts** come from nftables counters and are attributed to the
  rule, not to an application.

## Troubleshooting

```bash
sudo nft list table inet wirecee      # the rules WireCee installed
cat /var/lib/wirecee/logs/*.log       # daily engine logs
sudo wirecee --status
```

State, logs and the blocklist live in `/var/lib/wirecee`. Set
`WIRECEE_DATA_DIR` to use another directory.
