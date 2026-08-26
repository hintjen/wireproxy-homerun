> [!IMPORTANT]
> ### This is not upstream wireproxy
>
> This repository is [wireproxy](https://github.com/whyvl/wireproxy) carrying
> a set of changes that let it run **inside an application** — spawned by, or
> linked into, a mobile app — rather than only as a command-line tool. In
> short:
>
> - the port forwarders return errors instead of calling `log.Fatal`, and can
>   be stopped without exiting the process
> - the device's log output can be delivered to the caller
> - a config can be parsed from memory, not only from a file
> - an inbound UDP tunnel (`[UDPServerTunnel]`) alongside the TCP one
> - a connected-UDP bind for single-peer configs, and Android build targets
>
> **[What each change is for, and why → FORK.md](FORK.md)**
>
> Please report wireproxy bugs to
> **[whyvl/wireproxy](https://github.com/whyvl/wireproxy)**, not here. Issues
> here should be about the changes in `FORK.md` and nothing else.

# wireproxy, for Homerun

Everything about wireproxy itself — what it is, the config format, the
proxies and tunnels it offers, installing and running it, its maintainers and
sponsors — is in **upstream's README at
[whyvl/wireproxy](https://github.com/whyvl/wireproxy#readme)**. It is not
copied here, so it cannot go stale against the original.

What this repository changes, and why each change exists:
**[FORK.md](FORK.md)**.

## Building

```sh
go build ./cmd/wireproxy
go test ./...
make android-arm64      # the binary Homerun ships on Android; see FORK.md
```

## Licence

ISC, inherited from upstream, with copyright held by wireproxy's
contributors. See [LICENSE](LICENSE).
