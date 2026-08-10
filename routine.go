package wireproxy

import (
	"bytes"
	"context"
	srand "crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/device"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"

	"net/netip"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// errorLogger is the logger to print error message
var errorLogger = log.New(os.Stderr, "ERROR: ", log.LstdFlags)

// CredentialValidator stores the authentication data of a socks5 proxy
type CredentialValidator struct {
	username string
	password string
}

// VirtualTun stores a reference to netstack network and DNS configuration
type VirtualTun struct {
	Tnet          *netstack.Net
	Dev           *device.Device
	SystemDNS     bool
	Conf          *DeviceConfig
	ResolveConfig *ResolveConfig
	// PingRecord stores the last time an IP was pinged
	PingRecord     map[string]uint64
	PingRecordLock *sync.Mutex
}

// RoutineSpawner runs one tunnel (socks5, a static TCP route, a UDP forward)
// once the configuration is parsed.
//
// # Why this is three methods and not one
//
// It used to be a single blocking SpawnRoutine that called log.Fatal — that is,
// os.Exit — on every failure, including the perfectly ordinary one of a
// listener being closed on shutdown. That is survivable in a CLI whose only job
// is to run until killed. It is not survivable when this package is linked into
// an application: os.Exit takes the whole process, no defer runs, and nothing
// can recover. Stopping a tunnel would terminate the host app.
//
// Splitting Bind from Serve also makes the common failure — the port is already
// in use — an error the caller receives from Bind, rather than a log line that
// appears after it has already been told the tunnel started.
type RoutineSpawner interface {
	// Bind acquires whatever this routine listens on. Safe to call once.
	Bind(vt *VirtualTun) error

	// Serve runs until Close, returning nil for a deliberate shutdown and an
	// error for anything else. Bind must have succeeded first.
	Serve(vt *VirtualTun) error

	// Close releases the listener, causing Serve to return nil. Idempotent,
	// and safe to call from another goroutine.
	Close() error
}

// shutdown records that Close was asked for, so Serve can tell a deliberate
// stop from a fault.
//
// # Why intent and not the error
//
// Closing a listener is how shutdown works, so the resulting error is expected
// — but *which* error depends on who owns the listener. A host socket reports
// net.ErrClosed; a listener on the WireGuard interface belongs to gVisor's
// netstack and reports "endpoint is in invalid state", which is not
// net.ErrClosed and never will be. Matching on error values means tracking two
// unrelated error domains and getting it wrong the first time a third appears.
//
// That is not hypothetical: the netstack case is the one Homerun actually
// uses, and judging it by error value alone let a clean stop look like a
// failure — which in the CLI is log.Fatal, i.e. the exact process death this
// rework exists to remove.
//
// Recording the intent is both simpler and correct: if we asked it to stop,
// whatever it says on the way out is not a fault.
type shutdown struct{ closed atomic.Bool }

func (s *shutdown) markClosed()    { s.closed.Store(true) }
func (s *shutdown) stopping() bool { return s.closed.Load() }

// closedByUs reports whether an error is the ordinary consequence of Close.
//
// The intent check is the reliable half; the error check catches a listener
// closed by something other than our own Close.
func (s *shutdown) closedByUs(err error) bool {
	return err == nil || s.stopping() || errors.Is(err, net.ErrClosed)
}

type addressPort struct {
	address string
	port    uint16
}

// LookupAddr lookups a hostname.
// DNS traffic may or may not be routed depending on VirtualTun's setting
func (d VirtualTun) LookupAddr(ctx context.Context, name string) ([]string, error) {
	if d.SystemDNS {
		return net.DefaultResolver.LookupHost(ctx, name)
	}
	return d.Tnet.LookupContextHost(ctx, name)
}

// ResolveAddrWithContext resolves a hostname and returns an AddrPort.
// DNS traffic may or may not be routed depending on VirtualTun's setting
func (d VirtualTun) ResolveAddrWithContext(ctx context.Context, name string) (*netip.Addr, error) {
	addrs, err := d.LookupAddr(ctx, name)
	if err != nil {
		return nil, err
	}

	addrs_v4 := []netip.Addr{}
	addrs_v6 := []netip.Addr{}

	for _, saddr := range addrs {
		addr, err := netip.ParseAddr(saddr)
		if err == nil {
			if addr.Is4() {
				addrs_v4 = append(addrs_v4, addr)
			} else if addr.Is6() {
				addrs_v6 = append(addrs_v6, addr)
			}
		}
	}

	rand.Shuffle(len(addrs_v4), func(i, j int) {
		addrs_v4[i], addrs_v4[j] = addrs_v4[j], addrs_v4[i]
	})
	rand.Shuffle(len(addrs_v6), func(i, j int) {
		addrs_v6[i], addrs_v6[j] = addrs_v6[j], addrs_v6[i]
	})

	addrs_all := []netip.Addr{}

	switch d.ResolveConfig.ResolveStrategy {
	case "ipv4":
		addrs_all = append(addrs_v4, addrs_v6...)
	case "ipv6":
		addrs_all = append(addrs_v6, addrs_v4...)
	}

	if len(addrs_all) == 0 {
		return nil, errors.New("no address found for: " + name)
	}

	return &addrs_all[0], nil
}

// Resolve resolves a hostname and returns an IP.
// DNS traffic may or may not be routed depending on VirtualTun's setting
func (d VirtualTun) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	log.Printf("Resolving address for %s\n", name)

	addr, err := d.ResolveAddrWithContext(ctx, name)
	if err != nil {
		return nil, nil, err
	}

	return ctx, addr.AsSlice(), nil
}

func parseAddressPort(endpoint string) (*addressPort, error) {
	name, sport, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &net.OpError{Op: "dial", Err: errors.New("port must be numeric")}
	}

	return &addressPort{address: name, port: uint16(port)}, nil
}

func (d VirtualTun) resolveToAddrPort(endpoint *addressPort) (*netip.AddrPort, error) {
	addr, err := d.ResolveAddrWithContext(context.Background(), endpoint.address)
	if err != nil {
		return nil, err
	}

	addrPort := netip.AddrPortFrom(*addr, endpoint.port)
	return &addrPort, nil
}

// Bind acquires the socks5 listener.
func (config *Socks5Config) Bind(_ *VirtualTun) error {
	listener, err := net.Listen("tcp", config.BindAddress)
	if err != nil {
		return fmt.Errorf("socks5: cannot listen on %s: %w", config.BindAddress, err)
	}
	config.listener = listener
	return nil
}

// Serve runs the socks5 server until Close.
func (config *Socks5Config) Serve(vt *VirtualTun) error {
	if config.listener == nil {
		return errors.New("socks5: Serve called before Bind")
	}

	var authMethods []socks5.Authenticator
	if username := config.Username; username != "" {
		authMethods = append(authMethods, socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{username: config.Password},
		})
	} else {
		authMethods = append(authMethods, socks5.NoAuthAuthenticator{})
	}

	options := []socks5.Option{
		socks5.WithDial(vt.Tnet.DialContext),
		socks5.WithResolver(vt),
		socks5.WithAuthMethods(authMethods),
		socks5.WithBufferPool(bufferpool.NewPool(256 * 1024)),
	}

	if err := socks5.NewServer(options...).Serve(config.listener); err != nil && !config.closedByUs(err) {
		return fmt.Errorf("socks5: %w", err)
	}
	return nil
}

func (config *Socks5Config) Close() error {
	config.markClosed()
	return closeListener(config.listener)
}

// Bind acquires the HTTP proxy listener.
//
// TLS is applied here rather than in Serve because it is a property of the
// listener: HTTPServer.listen wrapped it at bind time, and binding plainly
// would quietly downgrade a configured HTTPS proxy to cleartext.
func (config *HTTPConfig) Bind(_ *VirtualTun) error {
	var (
		listener net.Listener
		err      error
	)
	if config.CertFile != "" && config.KeyFile != "" {
		var cert tls.Certificate
		cert, err = tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return fmt.Errorf("http proxy: cannot load certificate: %w", err)
		}
		listener, err = tls.Listen("tcp", config.BindAddress,
			&tls.Config{Certificates: []tls.Certificate{cert}})
	} else {
		listener, err = net.Listen("tcp", config.BindAddress)
	}
	if err != nil {
		return fmt.Errorf("http proxy: cannot listen on %s: %w", config.BindAddress, err)
	}
	config.listener = listener
	return nil
}

// Serve runs the HTTP proxy until Close.
func (config *HTTPConfig) Serve(vt *VirtualTun) error {
	if config.listener == nil {
		return errors.New("http proxy: Serve called before Bind")
	}

	server := &HTTPServer{
		config: config,
		dial:   vt.Tnet.Dial,
		auth:   CredentialValidator{config.Username, config.Password},
	}
	if config.Username != "" || config.Password != "" {
		server.authRequired = true
	}
	// The listener is already wrapped by Bind if TLS was configured.
	if err := server.Serve(config.listener); err != nil && !config.closedByUs(err) {
		return fmt.Errorf("http proxy: %w", err)
	}
	return nil
}

func (config *HTTPConfig) Close() error {
	config.markClosed()
	return closeListener(config.listener)
}

// Valid checks the authentication data in CredentialValidator and compare them
// to username and password in constant time.
func (c CredentialValidator) Valid(username, password string) bool {
	u := subtle.ConstantTimeCompare([]byte(c.username), []byte(username))
	p := subtle.ConstantTimeCompare([]byte(c.password), []byte(password))
	return u&p == 1
}

// connForward copy data from `from` to `to`
func connForward(from io.ReadWriteCloser, to io.ReadWriteCloser) {
	defer func() { _ = from.Close() }()
	defer func() { _ = to.Close() }()

	_, err := io.Copy(to, from)
	if err != nil {
		errorLogger.Printf("Cannot forward traffic: %s\n", err.Error())
	}
}

// tcpClientForward starts a new connection via wireguard and forward traffic from `conn`
func tcpClientForward(vt *VirtualTun, raddr *addressPort, conn net.Conn) {
	target, err := vt.resolveToAddrPort(raddr)
	if err != nil {
		errorLogger.Printf("TCP Server Tunnel to %s: %s\n", target, err.Error())
		return
	}

	tcpAddr := net.TCPAddrFromAddrPort(*target)

	sconn, err := vt.Tnet.DialTCP(tcpAddr)
	if err != nil {
		errorLogger.Printf("TCP Client Tunnel to %s: %s\n", target, err.Error())
		return
	}

	go connForward(sconn, conn)
	go connForward(conn, sconn)
}

// STDIOTcpForward starts a new connection via wireguard and forward traffic from `conn`
func STDIOTcpForward(vt *VirtualTun, raddr *addressPort, input *os.File, output *os.File) {
	target, err := vt.resolveToAddrPort(raddr)
	if err != nil {
		errorLogger.Printf("Name resolution error for %s: %s\n", raddr.address, err.Error())
		return
	}

	tcpAddr := net.TCPAddrFromAddrPort(*target)
	sconn, err := vt.Tnet.DialTCP(tcpAddr)
	if err != nil {
		errorLogger.Printf("TCP Client Tunnel to %s (%s): %s\n", target, tcpAddr, err.Error())
		return
	}

	go connForward(input, sconn)
	go connForward(sconn, output)
}

// Bind acquires the local listener this tunnel proxies from.
func (conf *TCPClientTunnelConfig) Bind(_ *VirtualTun) error {
	raddr, err := parseAddressPort(conf.Target)
	if err != nil {
		return fmt.Errorf("tcp client tunnel: bad target %q: %w", conf.Target, err)
	}
	conf.raddr = raddr

	listener, err := net.ListenTCP("tcp", conf.BindAddress)
	if err != nil {
		return fmt.Errorf("tcp client tunnel: cannot listen on %s: %w", conf.BindAddress, err)
	}
	conf.listener = listener
	return nil
}

// Serve accepts local connections and forwards each over WireGuard.
func (conf *TCPClientTunnelConfig) Serve(vt *VirtualTun) error {
	if conf.listener == nil {
		return errors.New("tcp client tunnel: Serve called before Bind")
	}

	for {
		conn, err := conf.listener.Accept()
		if err != nil {
			if conf.closedByUs(err) {
				return nil
			}
			return fmt.Errorf("tcp client tunnel: %w", err)
		}
		go tcpClientForward(vt, conf.raddr, conn)
	}
}

func (conf *TCPClientTunnelConfig) Close() error {
	conf.markClosed()
	return closeListener(conf.listener)
}

// Bind resolves the target. There is no listener: this tunnel dials out.
func (conf *STDIOTunnelConfig) Bind(_ *VirtualTun) error {
	raddr, err := parseAddressPort(conf.Target)
	if err != nil {
		return fmt.Errorf("stdio tunnel: bad target %q: %w", conf.Target, err)
	}
	conf.raddr = raddr
	return nil
}

// Serve plumbs the target to STDIN/STDOUT and returns immediately. The
// forwarding runs until those streams close, which is the process ending.
func (conf *STDIOTunnelConfig) Serve(vt *VirtualTun) error {
	if conf.raddr == nil {
		return errors.New("stdio tunnel: Serve called before Bind")
	}
	go STDIOTcpForward(vt, conf.raddr, conf.Input, conf.Output)
	return nil
}

// Close does nothing: STDIN and STDOUT belong to the caller.
func (conf *STDIOTunnelConfig) Close() error { return nil }

// tcpServerForward starts a new connection locally and forward traffic from `conn`
func tcpServerForward(vt *VirtualTun, raddr *addressPort, conn net.Conn) {
	target, err := vt.resolveToAddrPort(raddr)
	if err != nil {
		errorLogger.Printf("TCP Server Tunnel to %s: %s\n", target, err.Error())
		return
	}

	tcpAddr := net.TCPAddrFromAddrPort(*target)

	sconn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		errorLogger.Printf("TCP Server Tunnel to %s: %s\n", target, err.Error())
		return
	}

	go connForward(sconn, conn)
	go connForward(conn, sconn)

}

// Bind acquires the WireGuard-side listener.
//
// This is the routine Homerun depends on, and its accept loop is where the old
// log.Fatal did the most damage: closing the listener to stop a tunnel produced
// an error here, and the process exited.
func (conf *TCPServerTunnelConfig) Bind(vt *VirtualTun) error {
	raddr, err := parseAddressPort(conf.Target)
	if err != nil {
		return fmt.Errorf("tcp server tunnel: bad target %q: %w", conf.Target, err)
	}
	conf.raddr = raddr

	listener, err := vt.Tnet.ListenTCP(&net.TCPAddr{Port: conf.ListenPort})
	if err != nil {
		return fmt.Errorf(
			"tcp server tunnel: cannot listen on WireGuard port %d: %w", conf.ListenPort, err)
	}
	conf.listener = listener
	return nil
}

// Serve accepts from the WireGuard interface and forwards to the local target.
func (conf *TCPServerTunnelConfig) Serve(vt *VirtualTun) error {
	if conf.listener == nil {
		return errors.New("tcp server tunnel: Serve called before Bind")
	}

	for {
		conn, err := conf.listener.Accept()
		if err != nil {
			if conf.closedByUs(err) {
				return nil
			}
			return fmt.Errorf("tcp server tunnel: %w", err)
		}
		go tcpServerForward(vt, conf.raddr, conn)
	}
}

func (conf *TCPServerTunnelConfig) Close() error {
	conf.markClosed()
	return closeListener(conf.listener)
}

// closeListener closes c if it exists, tolerating a second close.
//
// A listener already closed reports it differently depending on who owns it,
// and none of those are failures worth surfacing from Close.
func closeListener(c io.Closer) error {
	if c == nil {
		return nil
	}
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func (d VirtualTun) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Health metric request: %s\n", r.URL.Path)
	switch path.Clean(r.URL.Path) {
	case "/readyz":
		body, err := json.Marshal(d.PingRecord)
		if err != nil {
			errorLogger.Printf("Failed to get device metrics: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		status := http.StatusOK
		for _, record := range d.PingRecord {
			lastPong := time.Unix(int64(record), 0)
			// +2 seconds to account for the time it takes to ping the IP
			if time.Since(lastPong) > time.Duration(d.Conf.CheckAliveInterval+2)*time.Second {
				status = http.StatusServiceUnavailable
				break
			}
		}

		w.WriteHeader(status)
		_, _ = w.Write(body)
		_, _ = w.Write([]byte("\n"))
	case "/metrics":
		get, err := d.Dev.IpcGet()
		if err != nil {
			errorLogger.Printf("Failed to get device metrics: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var buf bytes.Buffer
		for _, peer := range strings.Split(get, "\n") {
			pair := strings.SplitN(peer, "=", 2)
			if len(pair) != 2 {
				buf.WriteString(peer)
				continue
			}
			if pair[0] == "private_key" || pair[0] == "preshared_key" {
				pair[1] = "REDACTED"
			}
			buf.WriteString(pair[0])
			buf.WriteString("=")
			buf.WriteString(pair[1])
			buf.WriteString("\n")
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d VirtualTun) pingIPs() {
	for _, addr := range d.Conf.CheckAlive {
		socket, err := d.Tnet.Dial("ping", addr.String())
		if err != nil {
			errorLogger.Printf("Failed to ping %s: %s\n", addr, err.Error())
			continue
		}

		data := make([]byte, 16)
		_, _ = srand.Read(data)

		requestPing := icmp.Echo{
			Seq:  rand.Intn(1 << 16),
			Data: data,
		}

		var icmpBytes []byte
		if addr.Is4() {
			icmpBytes, _ = (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
		} else if addr.Is6() {
			icmpBytes, _ = (&icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Code: 0, Body: &requestPing}).Marshal(nil)
		} else {
			errorLogger.Printf("Failed to ping %s: invalid address: %s\n", addr, addr.String())
			continue
		}

		_ = socket.SetReadDeadline(time.Now().Add(time.Duration(d.Conf.CheckAliveInterval) * time.Second))
		_, err = socket.Write(icmpBytes)
		if err != nil {
			errorLogger.Printf("Failed to ping %s: %s\n", addr, err.Error())
			continue
		}

		addr := addr
		go func() {
			n, err := socket.Read(icmpBytes[:])
			if err != nil {
				errorLogger.Printf("Failed to read ping response from %s: %s\n", addr, err.Error())
				return
			}

			replyPacket, err := icmp.ParseMessage(1, icmpBytes[:n])
			if err != nil {
				errorLogger.Printf("Failed to parse ping response from %s: %s\n", addr, err.Error())
				return
			}

			if addr.Is4() {
				replyPing, ok := replyPacket.Body.(*icmp.Echo)
				if !ok {
					errorLogger.Printf("Failed to parse ping response from %s: invalid reply type: %s\n", addr, replyPacket.Type)
					return
				}
				if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
					errorLogger.Printf("Failed to parse ping response from %s: invalid ping reply: %v\n", addr, replyPing)
					return
				}
			}

			if addr.Is6() {
				replyPing, ok := replyPacket.Body.(*icmp.RawBody)
				if !ok {
					errorLogger.Printf("Failed to parse ping response from %s: invalid reply type: %s\n", addr, replyPacket.Type)
					return
				}

				seq := binary.BigEndian.Uint16(replyPing.Data[2:4])
				pongBody := replyPing.Data[4:]
				if !bytes.Equal(pongBody, requestPing.Data) || int(seq) != requestPing.Seq {
					errorLogger.Printf("Failed to parse ping response from %s: invalid ping reply: %v\n", addr, replyPing)
					return
				}
			}

			d.PingRecordLock.Lock()
			d.PingRecord[addr.String()] = uint64(time.Now().Unix())
			d.PingRecordLock.Unlock()

			defer func() { _ = socket.Close() }()
		}()
	}
}

func (d VirtualTun) StartPingIPs() {
	d.PingRecordLock.Lock()
	for _, addr := range d.Conf.CheckAlive {
		d.PingRecord[addr.String()] = 0
	}
	d.PingRecordLock.Unlock()

	go func() {
		for {
			d.pingIPs()
			time.Sleep(time.Duration(d.Conf.CheckAliveInterval) * time.Second)
		}
	}()
}
