package wireproxy

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func tcpRecovery(t *testing.T, tnet *netstack.Net) tcpip.TCPRecovery {
	t.Helper()
	s, err := netstackStack(tnet)
	if err != nil {
		t.Fatalf("netstackStack: %v", err)
	}
	var opt tcpip.TCPRecovery
	if tcpipErr := s.TransportProtocolOption(tcp.ProtocolNumber, &opt); tcpipErr != nil {
		t.Fatalf("reading TCPRecovery: %v", tcpipErr)
	}
	return opt
}

// The stack is reached through an unexported field of wireguard-go's
// netstack.Net. This is the test that fails when a wireguard-go or gVisor bump
// moves that field or changes the default, instead of connections stalling
// under packet loss again with nothing to show for it.
func TestRACKIsOffAfterDisable(t *testing.T) {
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1280)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	defer func() { _ = tun.Close() }()

	if before := tcpRecovery(t, tnet); before == 0 {
		t.Log("netstack's default no longer enables RACK; disableRACK may have become unnecessary")
	}
	if err := disableRACK(tnet); err != nil {
		t.Fatalf("disableRACK: %v", err)
	}
	if after := tcpRecovery(t, tnet); after != 0 {
		t.Fatalf("TCPRecovery = %#x after disableRACK, want 0", after)
	}
}

func TestNetstackStackRejectsNil(t *testing.T) {
	if _, err := netstackStack(nil); err == nil {
		t.Fatal("netstackStack(nil) returned no error")
	}
}
