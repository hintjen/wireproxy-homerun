package wireproxy

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/windtf/wireproxy/clientbind"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// A device on a ClientOnlyBind whose peer is a plain UDP socket on loopback,
// so the test can see every packet the tunnel sends. No keepalive: an idle
// tunnel sends nothing, and anything that arrives was caused by the test.
func roamingDevice(t *testing.T) (*device.Device, *clientbind.ClientOnlyBind, *device.Peer, *net.UDPConn) {
	t.Helper()
	gateway, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Close() })

	conf, err := ParseConfigString(fmt.Sprintf(`[Interface]
PrivateKey = OMhFP0Xt3AKk7oNXFVpXsPqFPRhKa5PHSCiKX2h2XHo=
Address = 10.0.0.2/24

[Peer]
PublicKey = 7ZKMOxBmLLXCKCXeGgLLW1LtRYKPvNvhSTk0kPYWUXA=
Endpoint = %s
AllowedIPs = 10.0.0.1/32
`, gateway.LocalAddr()))
	if err != nil {
		t.Fatal(err)
	}
	setting, err := CreateIPCRequest(conf.Device)
	if err != nil {
		t.Fatal(err)
	}
	tun, _, err := netstack.CreateNetTUN(setting.DeviceAddr, setting.DNS, 1280)
	if err != nil {
		t.Fatal(err)
	}
	bind, err := clientbind.New(gateway.LocalAddr().(*net.UDPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet(setting.IpcRequest); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)

	var key device.NoisePublicKey
	if err := key.FromHex(conf.Device.Peers[0].PublicKey); err != nil {
		t.Fatal(err)
	}
	return dev, bind, dev.LookupPeer(key), gateway
}

// received returns the source of the next packet the gateway gets within d,
// or false if none came.
func received(gateway *net.UDPConn, d time.Duration) (netip.AddrPort, bool) {
	_ = gateway.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 2048)
	_, from, err := gateway.ReadFromUDPAddrPort(buf)
	return from, err == nil
}

// The whole point: when the route to the peer moves, the tunnel rebinds and
// says so to the peer at once, without waiting for traffic or a keepalive.
// An idle tunnel that did not follow the route would send nothing here.
func TestAMovedRouteRebindsAndReachesThePeer(t *testing.T) {
	dev, bind, peer, gateway := roamingDevice(t)
	here := netip.MustParseAddr("127.0.0.1")
	route := make(chan netip.Addr, 1)
	route <- here
	current := here
	bind.SetRoute(func(string, netip.AddrPort) (netip.Addr, error) {
		select {
		case current = <-route:
		default:
		}
		return current, nil
	})

	done := make(chan struct{})
	go func() {
		followRouteEvery(dev, bind, peer, device.NewLogger(device.LogLevelSilent, ""), 20*time.Millisecond)
		close(done)
	}()

	if _, got := received(gateway, 300*time.Millisecond); got {
		t.Fatal("the route has not moved, yet the tunnel sent something")
	}

	// The fake route never matches the socket again, so the watcher rebinds on
	// every tick. Each rebind is a new socket on a new ephemeral port; a
	// keepalive down the old socket alone would arrive from one port only.
	// Nothing answers here, so there is no session: the first packet is a
	// handshake initiation, and the next is its retry, which wireguard-go
	// sends no sooner than RekeyTimeout (5 s) later. Hence the wait.
	route <- netip.MustParseAddr("192.0.0.4")
	first, got := received(gateway, 3*time.Second)
	if !got {
		t.Fatal("the route moved and nothing reached the peer")
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		from, got := received(gateway, time.Until(deadline))
		if !got {
			t.Fatalf("every packet came from %v: the socket was never reopened", first)
		}
		if from.Port() != first.Port() {
			break
		}
	}

	dev.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("followRoute did not stop when the device closed")
	}
}
