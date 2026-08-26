# About this repository

Upstream is [whyvl/wireproxy](https://github.com/whyvl/wireproxy), a
userspace WireGuard client with a SOCKS5/HTTP proxy and port forwarders, ISC
licensed. This repository carries that work with a set of changes on top, and
merges upstream `master` on a schedule.

## What it is for

wireproxy was written to be a **command-line tool**: it runs until killed,
owns stderr, and when anything goes wrong it calls `log.Fatal`, which is
`os.Exit(1)`.

[Homerun](https://gethomerun.app) runs it **inside an application** — spawned
by Homerun Desktop and by Homerun Go on Android, and on iOS linked into
Homerun Go as a library, because iOS cannot spawn a process at all — to make a phone-hosted Minecraft server reachable through the
Homerun gateway. A phone on cellular sits behind CGNAT; there is no
port-forwarding alternative. In that setting:

- **`os.Exit` is the application dying.** Closing a listener is how a tunnel
  is stopped, and in upstream the accept loop answered that with
  `log.Fatal`. Stopping the tunnel exited the process.
- **stderr belongs to nobody.** The device's "handshake did not complete,
  retrying" lines are the only way to tell revoked credentials from a slow
  network, and they went to a stream no one reads.
- **A config on disk is a private key on disk.** The library only parsed
  files.
- **Players connect over UDP.** Bedrock (RakNet) and voice chat need an
  inbound UDP forwarder; upstream forwards TCP only.

So the job of this repository is: **make a command-line tunnel safe to link
into an application, and give it an inbound UDP tunnel, without changing
what it does for anyone running the binary.** Everything here should be
reviewable against that sentence.

## What is changed

| Where | Change | Why |
|---|---|---|
| `routine.go`, `udp_proxy.go`, `udp_server_tunnel.go`, `http.go` | `RoutineSpawner` is `Bind` / `Serve` / `Close`; the thirteen `log.Fatal` calls return errors; shutdown is judged by intent (`Close` was asked for), not by which error a listener reports | A closed listener on a host socket reports `net.ErrClosed`; one on the WireGuard interface belongs to gVisor's netstack and reports `endpoint is in invalid state`. Matching on error values made a clean stop look like a crash. `Bind` is separate from `Serve` so "port already in use" is an error the caller gets up front. Two latent bugs fixed on the way: UDP read loops spun forever on a closed socket, and session reapers never exited. |
| `config.go`, `udp_server_tunnel.go` | `[UDPServerTunnel]`: forward UDP arriving on the WireGuard side to a local target | Bedrock and voice are UDP. Upstream has `TCPServerTunnel` only. |
| `wireguard.go` | `StartWireguardWithLogger` — the device's log output delivered to the caller; `StartWireguard` delegates to it | A tunnel whose credentials were revoked retries for ever and looks exactly like a slow network until you can count the handshake lines. |
| `config.go` | `ParseConfigString` — parse a config held in memory; shares `parseConfigSource` with `ParseConfig` so the two cannot diverge | The file a consumer would otherwise have to write contains the WireGuard private key. |
| `clientbind/`, `wireguard.go` | A connected-UDP `conn.Bind` for single-peer configs with a resolved endpoint; anything else falls back to upstream's default bind | A wildcard UDP listener makes Windows Defender Firewall prompt on first run, or silently create Inbound Block rules. A connected socket does neither, and is the right shape for a single-peer client anyway. Needs nothing unexported from wireguard-go, so it is a package here rather than a fork of wireguard-go. |
| `cmd/wireproxy/landlock_android.go`, `landlock_other.go` | Landlock is compiled out on Android | Android's seccomp filter answers the Landlock syscall with `SIGSYS`, not `ENOSYS`, so `BestEffort()` cannot degrade — the process is killed. |
| `Makefile`, `.github/workflows/android.yml` | `android-arm64` / `android-amd64` targets, and CI that asserts the result is an Android binary | See *Android* below; `GOOS=linux` builds a binary that will not start on a phone, and nothing else notices. |

The `RoutineSpawner`, logger and `ParseConfigString` changes are the kind
that could go upstream. `UDPServerTunnel` and the Android build are ours.

### What this repository no longer carries

Before it was a fork of upstream, this repository was a flat import of
wireproxy *and* wireguard-go, and
patched wireguard-go's netstack `Close` to call `stack.Close()` and
`stack.Wait()`: `RemoveNIC` alone left one TCP dispatcher goroutine per core
behind on every tunnel stop, which on a phone that starts and stops a server
all day accumulates against the memory limit. wireguard-go has since taken
the `Close()` half itself (`tun/netstack/tun.go`, 2025), and the stack is
not reachable from outside the package for the `Wait()`. Measured with the
consumer's repeated start/stop test against the upstream module, with and
without a pause between stop and the next start: goroutines hold at
baseline across five cycles. So wireguard-go comes from the module proxy,
unpatched. The pre-fork history is not published: it named a
player's server and a gateway endpoint, so it is kept privately by
Homerun rather than as a branch here.

## Building

```bash
go build ./cmd/wireproxy
go test ./...
```

### Android

```sh
make android-arm64      # what ships; no NDK required
make android-amd64 \
  CC=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/<host>/bin/x86_64-linux-android26-clang
```

Output lands in `dist/android/<abi>/libwireproxy.so`. Three things about
this target are easy to get wrong:

- **`GOOS=android`, never `GOOS=linux`.** A `linux/arm64` PIE binary builds
  without complaint and then will not start on a phone: Go stamps
  `PT_INTERP` as `/lib/ld-linux-aarch64.so.1`, a glibc path bionic does not
  have. `GOOS=android` emits `/system/bin/linker64`. CI asserts this rather
  than trusting it.
- **PIE is mandatory.** Android has refused to exec non-PIE binaries since
  API 21. `GOOS=android` is PIE by default — but only on that GOOS.
- **arm64 needs no NDK; amd64 does.** Go reports
  `android/amd64 requires external (cgo) linking`. amd64 exists only for
  the emulator, so the asymmetry costs nothing on the shipping path.

The `.so` name is not a mistake. Android's packager only extracts files
matching `lib*.so` into `nativeLibraryDir`, and since API 29 that is the only
directory an app may exec from. It is an executable.

## Staying current with upstream

Upstream `master` is merged in on a schedule and opened as a pull request
rather than pushed; the fork's CI on the PR is the gate. The automation
itself is not published here — it is specific to one build host and of no
use to anyone else.

Consumers should pin an exact revision rather than a branch.

## Licence

ISC, inherited from upstream, with copyright held by wireproxy's
contributors. See `LICENSE`.
