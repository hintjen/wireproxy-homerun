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
//     change requires Close and a new bind.
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
}

var _ conn.Bind = (*ClientOnlyBind)(nil)

// New returns a bind for the given peer endpoint. It does not open a socket;
// that happens in Open, as with every conn.Bind.
func New(peer netip.AddrPort) (*ClientOnlyBind, error) {
	if !peer.IsValid() {
		return nil, errors.New("clientbind: invalid peer endpoint")
	}
	return &ClientOnlyBind{peer: peer}, nil
}

// Open dials the peer. The port argument is ignored (see the package
// comment); the returned port is the ephemeral local port the OS chose.
func (b *ClientOnlyBind) Open(_ uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	network := "udp4"
	if b.peer.Addr().Is6() && !b.peer.Addr().Is4In6() {
		network = "udp6"
	}
	c, err := net.DialUDP(network, nil, net.UDPAddrFromAddrPort(b.peer))
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
