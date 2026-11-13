package wireproxy

import (
	"errors"
	"fmt"
	"reflect"
	"unsafe"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// # Why RACK is turned off
//
// Every TCP connection that crosses the tunnel is carried by gVisor's netstack,
// not by the operating system. With netstack's default loss recovery (RACK,
// with tail loss probes) a sender that loses a short run of packets can stop
// retransmitting: it holds unacknowledged data, goes on acknowledging what the
// peer sends, and sends nothing of its own for 10 to 30 seconds. Nothing is
// logged, because nothing has failed -- the connection is open and the peer's
// data is arriving.
//
// For a TCPServerTunnel in front of a game server on a home line that is a
// player frozen and then disconnected: a Minecraft client gives up after 30
// seconds without data. Measured with a WireGuard peer on kernel TCP, a 20 Hz
// stream through a TCPServerTunnel, and 300 ms of dropped packets every 10
// seconds: four connections stalled 23 to 27 times in five minutes, for up to
// 20.7 seconds each. With RACK off, under the same loss: none. The gVisor
// revisions of 2023-09 and 2025-05 behave the same, so this is not something
// a dependency bump has fixed.
//
// With RACK off netstack recovers the classic way -- SACK-based fast
// retransmit on duplicate ACKs, and the retransmission timer. SACK stays on;
// wireguard-go enables it.

// netstackStack returns the gVisor stack behind a netstack.Net.
//
// wireguard-go does not export it, and the option below can only be set on the
// stack, so this reads the unexported field. That is the alternative to
// carrying a copy of wireguard-go's tun/netstack for one line. If wireguard-go
// renames or retypes the field this returns an error, StartWireguard fails,
// and TestRACKIsOffAfterDisable fails with it -- a dependency bump cannot
// quietly bring the stalls back.
func netstackStack(tnet *netstack.Net) (*stack.Stack, error) {
	if tnet == nil {
		return nil, errors.New("netstack: nil Net")
	}
	f := reflect.ValueOf(tnet).Elem().FieldByName("stack")
	if !f.IsValid() {
		return nil, errors.New("netstack: Net has no field named stack (wireguard-go changed)")
	}
	if f.Type() != reflect.TypeOf((*stack.Stack)(nil)) {
		return nil, fmt.Errorf("netstack: Net.stack is a %s, not a *stack.Stack (wireguard-go changed)", f.Type())
	}
	s := *(**stack.Stack)(unsafe.Pointer(f.UnsafeAddr())) // #nosec G103 -- reading an unexported field, see above
	if s == nil {
		return nil, errors.New("netstack: Net.stack is nil")
	}
	return s, nil
}

// disableRACK turns off RACK/TLP loss recovery for every TCP endpoint the
// stack creates from now on. It must run before any listener or dialer does.
func disableRACK(tnet *netstack.Net) error {
	s, err := netstackStack(tnet)
	if err != nil {
		return err
	}
	opt := tcpip.TCPRecovery(0)
	if tcpipErr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); tcpipErr != nil {
		return fmt.Errorf("could not disable RACK: %v", tcpipErr)
	}
	return nil
}
