// Package clientbind provides ClientOnlyBind, a single-peer, outbound-only
// conn.Bind for wireguard-go.
//
// It uses net.DialUDP to a fixed peer, producing a connected UDP socket. On
// Windows this avoids WFP's wildcard-listener classification (which
// StdNetBind and WinRingBind both trigger via a wildcard bind) and so
// prevents the first-run firewall prompt and the silent inbound-block rule
// that Windows Defender Firewall otherwise creates for an unrecognised
// binary. A connected socket is also simply the right shape for a
// single-peer client on any platform.
//
// Constraints:
//   - Single peer per bind. Multi-peer configs must use a different bind.
//   - No roaming: the peer endpoint is fixed at construction. An endpoint
//     change requires Close and a new bind. The *local* side does move:
//     Moved says when the route to the peer now leaves from another address,
//     and the device's BindUpdate reopens the socket there (see
//     followRoute in the wireproxy package).
//   - The listen port from the config is ignored; the OS assigns an
//     ephemeral local port. wireproxy's client use case does not need a
//     fixed local port.
//
// It lives here rather than in a fork of wireguard-go because it needs
// nothing unexported from package conn.
package clientbind

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// ClientOnlyBind is a conn.Bind over one connected UDP socket to one peer.
type ClientOnlyBind struct {
	mu   sync.Mutex
	peer netip.AddrPort
	conn *net.UDPConn

	// route answers which local address the system would use for the peer
	// now. A field so a test can move the route without moving a network.
	route func(network string, peer netip.AddrPort) (netip.Addr, error)
}

var _ conn.Bind = (*ClientOnlyBind)(nil)

// New returns a bind for the given peer endpoint. It does not open a socket;
// that happens in Open, as with every conn.Bind.
func New(peer netip.AddrPort) (*ClientOnlyBind, error) {
	if !peer.IsValid() {
		return nil, errors.New("clientbind: invalid peer endpoint")
	}
	return &ClientOnlyBind{peer: peer, route: routeTo}, nil
}

func networkFor(peer netip.AddrPort) string {
	if peer.Addr().Is6() && !peer.Addr().Is4In6() {
		return "udp6"
	}
	return "udp4"
}

// routeTo asks the routing table which local address reaches peer, by
// connecting a UDP socket. Connecting a UDP socket sends nothing.
func routeTo(network string, peer netip.AddrPort) (netip.Addr, error) {
	c, err := net.DialUDP(network, nil, net.UDPAddrFromAddrPort(peer))
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}

// SetRoute replaces how Moved asks for the current route to the peer. For
// tests, which need to move a route without moving a network.
func (b *ClientOnlyBind) SetRoute(route func(network string, peer netip.AddrPort) (netip.Addr, error)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.route = route
}

// Moved reports whether the system now reaches the peer from a different
// local address than the open socket was given, and both addresses.
//
// # Why this exists
//
// A connected socket keeps the local address it was given at Open for its
// whole life. When that address goes away — a phone turning Wi-Fi off and
// carrying on over cellular, a laptop changing networks — every Send fails
// with "network is unreachable" and nothing ever reopens the socket: the
// tunnel stays dead until the process restarts. Asking the routing table
// again is cheap, sends nothing, and is the same question on every platform.
//
// No route at all (no network yet) is not a move: there is nothing better to
// rebind to, and the next check will see whatever comes up.
func (b *ClientOnlyBind) Moved() (from, to netip.Addr, moved bool) {
	b.mu.Lock()
	c, route := b.conn, b.route
	b.mu.Unlock()
	if c == nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	from = c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
	to, err := route(networkFor(b.peer), b.peer)
	if err != nil || !to.IsValid() {
		return from, netip.Addr{}, false
	}
	return from, to, to != from
}

// Open dials the peer. The port argument is ignored (see the package
// comment); the returned port is the ephemeral local port the OS chose.
func (b *ClientOnlyBind) Open(_ uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	c, err := net.DialUDP(networkFor(b.peer), nil, net.UDPAddrFromAddrPort(b.peer))
	if err != nil {
		return nil, 0, err
	}
	b.conn = c

	localPort := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	peerEP := &conn.StdNetEndpoint{AddrPort: b.peer}

	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := c.Read(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = peerEP
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, localPort, nil
}

// Send writes each buffer to the connected peer. The endpoint argument is
// ignored: a connected socket has exactly one destination.
func (b *ClientOnlyBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	b.mu.Lock()
	c := b.conn
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	for _, p := range bufs {
		if _, err := c.Write(p); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the socket. Open/closed state is tracked by conn != nil rather
// than a flag, so the device's BindUpdate Close-then-Open cycle works.
func (b *ClientOnlyBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn == nil {
		return nil
	}
	err := b.conn.Close()
	b.conn = nil
	return err
}

// SetMark is a no-op; fwmark has no meaning for a connected client socket.
func (b *ClientOnlyBind) SetMark(uint32) error { return nil }

// BatchSize is 1: one connected socket, one packet per receive.
func (b *ClientOnlyBind) BatchSize() int { return 1 }

// ParseEndpoint accepts only the configured peer, as a *conn.StdNetEndpoint.
func (b *ClientOnlyBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	if ap != b.peer {
		return nil, errors.New("clientbind: configured peer endpoint mismatch")
	}
	return &conn.StdNetEndpoint{AddrPort: ap}, nil
}
