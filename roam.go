package wireproxy

import (
	"time"

	"github.com/windtf/wireproxy/clientbind"
	"golang.zx2c4.com/wireguard/device"
)

// roamInterval is how often the route to the peer is checked. A tunnel whose
// network went away is dead until this notices, so it is short; a check is
// one connect() on a UDP socket, which sends nothing.
const roamInterval = 2 * time.Second

// followRoute keeps a ClientOnlyBind on whichever network now reaches the
// peer, until the device closes.
//
// # Why this exists
//
// ClientOnlyBind's socket is connected, so it keeps the local address it was
// opened with. A host that changes networks while the tunnel is up — a phone
// hosting a server that turns Wi-Fi off and carries on over cellular, a
// laptop moving between networks — loses that address, and every packet after
// fails with "network is unreachable" for as long as the process lives. Seen
// on a Pixel 9 Pro XL hosting a server: the tunnel stayed dead until the
// server was restarted.
//
// BindUpdate is wireguard-go's own answer to a moved network: it closes the
// bind and opens it again, which re-dials the peer from the address the route
// now leaves from. The session keys survive it, and so does every connection
// inside the tunnel's netstack. The gateway learns the new address from the
// first authenticated packet that arrives from it, so one is sent at once
// rather than waiting up to a keepalive interval for the next.
func followRoute(dev *device.Device, bind *clientbind.ClientOnlyBind, peer *device.Peer, logger *device.Logger) {
	followRouteEvery(dev, bind, peer, logger, roamInterval)
}

func followRouteEvery(dev *device.Device, bind *clientbind.ClientOnlyBind, peer *device.Peer, logger *device.Logger, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-dev.Wait():
			return
		case <-tick.C:
		}
		from, to, moved := bind.Moved()
		if !moved {
			continue
		}
		logger.Verbosef("Route to the peer moved from %v to %v; rebinding", from, to)
		if err := dev.BindUpdate(); err != nil {
			logger.Errorf("Rebinding after the route moved: %v", err)
			continue
		}
		if peer != nil {
			peer.SendKeepalive()
		}
	}
}
