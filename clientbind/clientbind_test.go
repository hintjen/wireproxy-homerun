package clientbind

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

// A peer on loopback that nobody reads: Open only needs somewhere to dial.
func peer(t *testing.T) netip.AddrPort {
	t.Helper()
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l.LocalAddr().(*net.UDPAddr).AddrPort()
}

func opened(t *testing.T) *ClientOnlyBind {
	t.Helper()
	b, err := New(peer(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestTheRealRouteToALoopbackPeerHasNotMoved(t *testing.T) {
	b := opened(t)
	from, to, moved := b.Moved()
	if moved {
		t.Fatalf("nothing moved, yet Moved says %v -> %v", from, to)
	}
	if from != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("the socket's address is %v", from)
	}
}

// The phone that turned Wi-Fi off: the socket is still on the old address and
// the route now leaves from another.
func TestARouteFromAnotherAddressIsAMove(t *testing.T) {
	b := opened(t)
	cellular := netip.MustParseAddr("192.0.0.4")
	b.SetRoute(func(string, netip.AddrPort) (netip.Addr, error) { return cellular, nil })
	from, to, moved := b.Moved()
	if !moved || to != cellular || from != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("got %v -> %v moved=%v", from, to, moved)
	}
}

// No network at all is nothing to rebind to.
func TestNoRouteIsNotAMove(t *testing.T) {
	b := opened(t)
	b.SetRoute(func(string, netip.AddrPort) (netip.Addr, error) {
		return netip.Addr{}, errors.New("network is unreachable")
	})
	if _, _, moved := b.Moved(); moved {
		t.Fatal("no route reported as a move")
	}
}

func TestAClosedBindHasNothingToMove(t *testing.T) {
	b, err := New(peer(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, moved := b.Moved(); moved {
		t.Fatal("a bind that was never opened reported a move")
	}
}
