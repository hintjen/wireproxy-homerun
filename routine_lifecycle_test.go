package wireproxy

import (
	"net"
	"testing"
	"time"
)

// These tests exist because of one property: a routine must be able to stop
// without taking the process with it.
//
// Before the Bind/Serve/Close split, every one of them would have killed this
// test binary rather than failed — `log.Fatal` is `os.Exit(1)`, so there is no
// assertion to reach and no output to read. "The test suite vanished" was the
// failure mode. That is what makes these worth having: they are the difference
// between a claim and a fact.
//
// Everything binds port 0 and lets the OS choose. Picking a port by binding and
// releasing it first looks tidier and is wrong twice: it races anything else on
// the machine, and a free TCP port says nothing about the same number in UDP's
// separate namespace.

func tcpClientTunnel(t *testing.T) *TCPClientTunnelConfig {
	t.Helper()
	return &TCPClientTunnelConfig{
		BindAddress: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		Target:      "10.0.0.1:80",
	}
}

// serveUntilClosed runs Serve, closes the routine, and asserts the shutdown was
// clean and prompt.
func serveUntilClosed(t *testing.T, spawner RoutineSpawner) {
	t.Helper()

	served := make(chan error, 1)
	go func() { served <- spawner.Serve(&VirtualTun{}) }()

	// Let the accept loop actually block before pulling the listener out.
	time.Sleep(50 * time.Millisecond)
	if err := spawner.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("a deliberate shutdown must return nil, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
}

// The headline: closing a listener is how shutdown works, and it must be
// ordinary rather than fatal.
func TestCloseMakesServeReturnCleanly(t *testing.T) {
	conf := tcpClientTunnel(t)
	if err := conf.Bind(nil); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	serveUntilClosed(t, conf)
}

// The reason Bind is separate: a port conflict is the common failure, and the
// caller has to be able to tell the user rather than read it in a log later.
func TestBindReportsAPortConflict(t *testing.T) {
	holder, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not hold a port: %v", err)
	}
	defer func() { _ = holder.Close() }()

	conf := tcpClientTunnel(t)
	conf.BindAddress = holder.Addr().(*net.TCPAddr)

	if err := conf.Bind(nil); err == nil {
		t.Fatal("binding an occupied port must be an error, not an exit")
	}
}

// Stop is called from Kotlin/Swift on paths that can overlap. A second Close
// must be a no-op, not a panic and not an error.
func TestCloseIsIdempotent(t *testing.T) {
	conf := tcpClientTunnel(t)
	if err := conf.Bind(nil); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := conf.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := conf.Close(); err != nil {
		t.Fatalf("second Close must be a no-op, got %v", err)
	}
}

// Closing something that was never bound is also legal — a host that failed
// partway through startup still calls Stop on everything.
func TestCloseWithoutBindIsSafe(t *testing.T) {
	if err := tcpClientTunnel(t).Close(); err != nil {
		t.Fatalf("Close without Bind: %v", err)
	}
}

// Misuse is an error rather than a nil dereference.
func TestServeBeforeBindIsAnError(t *testing.T) {
	if err := tcpClientTunnel(t).Serve(&VirtualTun{}); err == nil {
		t.Fatal("Serve before Bind must error")
	}
}

// The same contract for the socks5, HTTP and SNI routines, which bind ordinary
// local listeners and used to exit on exactly the same paths.
func TestProxiesStopCleanly(t *testing.T) {
	for _, tc := range []struct {
		name    string
		spawner RoutineSpawner
	}{
		{"socks5", &Socks5Config{BindAddress: "127.0.0.1:0"}},
		{"http", &HTTPConfig{BindAddress: "127.0.0.1:0"}},
		{"sni", &SNIConfig{BindAddress: "127.0.0.1:0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.spawner.Bind(nil); err != nil {
				t.Fatalf("Bind: %v", err)
			}
			serveUntilClosed(t, tc.spawner)
		})
	}
}

// The UDP proxy's read loop used to `continue` on every error. A closed
// listener returns ErrClosed for ever, so shutdown would have become a busy
// loop pinning a core — reachable only once Close existed at all.
func TestUDPProxyStopsRatherThanSpinning(t *testing.T) {
	conf := &UDPProxyTunnelConfig{BindAddress: "127.0.0.1:0", Target: "10.0.0.1:80"}
	if err := conf.Bind(nil); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	serveUntilClosed(t, conf)
}
