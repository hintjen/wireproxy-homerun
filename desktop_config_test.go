package wireproxy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

// The config Homerun Desktop actually runs: inbound Java over TCP and voice
// chat over UDP, both landing on the WireGuard interface and forwarded to
// loopback. Ports are the gateway's fixed ones.
//
// This exists to answer one question directly — does the Bind/Serve/Close
// rework change what the shipping desktop sees? The desktop spawns a binary
// built from this package, so a regression here reaches it.
const desktopConfig = `[Interface]
PrivateKey = OMhFP0Xt3AKk7oNXFVpXsPqFPRhKa5PHSCiKX2h2XHo=
Address = 10.0.0.2/24
MTU = 1280

[Peer]
PublicKey = 7ZKMOxBmLLXCKCXeGgLLW1LtRYKPvNvhSTk0kPYWUXA=
Endpoint = 192.0.2.1:51820
AllowedIPs = 10.0.0.1/32
PersistentKeepalive = 30

[TCPServerTunnel]
ListenPort = 25565
Target = 127.0.0.1:25565

[UDPServerTunnel]
ListenPort = 24454
Target = 127.0.0.1:24454
`

// startLikeTheCLI reproduces cmd/wireproxy/main.go's sequence: bind everything,
// then serve everything. If this diverges from main.go, the test is worthless —
// keep them in step.
func startLikeTheCLI(t *testing.T, conf *Configuration) (*VirtualTun, chan error) {
	t.Helper()

	tun, err := StartWireguardWithLogger(conf, nil)
	if err != nil {
		t.Fatalf("StartWireguard: %v", err)
	}

	for _, spawner := range conf.Routines {
		if err := spawner.Bind(tun); err != nil {
			t.Fatalf("Bind: %v", err)
		}
	}

	served := make(chan error, len(conf.Routines))
	for _, spawner := range conf.Routines {
		go func(s RoutineSpawner) { served <- s.Serve(tun) }(spawner)
	}
	return tun, served
}

// The forwards must actually accept on the WireGuard interface. Dialling our
// own address through the netstack exercises the real path a player's traffic
// takes after the gateway hands it over — no peer, and no network, required.
func TestDesktopConfigAcceptsOnTheWireguardInterface(t *testing.T) {
	conf, err := ParseConfigString(desktopConfig)
	if err != nil {
		t.Fatalf("ParseConfigString: %v", err)
	}
	if len(conf.Routines) != 2 {
		t.Fatalf("expected 2 routines, got %d", len(conf.Routines))
	}

	tun, served := startLikeTheCLI(t, conf)
	defer tun.Dev.Close()

	// Give the accept loops a moment to be waiting.
	time.Sleep(100 * time.Millisecond)

	conn, err := tun.Tnet.Dial("tcp", "10.0.0.2:25565")
	if err != nil {
		t.Fatalf("the Java forward is not accepting on the WireGuard interface: %v", err)
	}
	_ = conn.Close()

	// Nothing should have fallen over.
	select {
	case err := <-served:
		t.Fatalf("a routine exited while serving: %v", err)
	default:
	}

	// And shutdown is clean for both.
	for _, spawner := range conf.Routines {
		if err := spawner.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}
	for i := 0; i < len(conf.Routines); i++ {
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("shutdown must return nil, got %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("a routine did not stop after Close")
		}
	}
}

// The CLI's original entry point must still work, since that is what the
// desktop binary calls.
func TestDesktopConfigViaStartWireguard(t *testing.T) {
	conf, err := ParseConfig(writeTemp(t, desktopConfig))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	tun, err := StartWireguard(conf, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("StartWireguard: %v", err)
	}
	defer tun.Dev.Close()

	for _, spawner := range conf.Routines {
		if err := spawner.Bind(tun); err != nil {
			t.Fatalf("Bind: %v", err)
		}
		defer func(s RoutineSpawner) { _ = s.Close() }(spawner)
	}
}

// A port conflict on the WireGuard interface must be an error, not an exit.
// Before the rework this test would have terminated the test binary.
func TestDuplicateListenPortIsReported(t *testing.T) {
	conf, err := ParseConfigString(desktopConfig)
	if err != nil {
		t.Fatalf("ParseConfigString: %v", err)
	}
	tun, err := StartWireguardWithLogger(conf, nil)
	if err != nil {
		t.Fatalf("StartWireguard: %v", err)
	}
	defer tun.Dev.Close()

	first := &TCPServerTunnelConfig{ListenPort: 25565, Target: "127.0.0.1:25565"}
	if err := first.Bind(tun); err != nil {
		t.Fatalf("first Bind: %v", err)
	}
	defer func() { _ = first.Close() }()

	second := &TCPServerTunnelConfig{ListenPort: 25565, Target: "127.0.0.1:25565"}
	if err := second.Bind(tun); err == nil {
		_ = second.Close()
		t.Fatal("binding the same WireGuard port twice must be an error")
	}
}

func writeTemp(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wireproxy.conf")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("could not write the fixture: %v", err)
	}
	return path
}
