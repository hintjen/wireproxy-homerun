package wireproxy

import (
	"bytes"
	"fmt"
	"sync"

	"net/netip"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/windtf/wireproxy/clientbind"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// DeviceSetting contains the parameters for setting up a tun interface
type DeviceSetting struct {
	IpcRequest string
	DNS        []netip.Addr
	DeviceAddr []netip.Addr
	MTU        int
}

// CreateIPCRequest serialize the config into an IPC request and DeviceSetting
func CreateIPCRequest(conf *DeviceConfig) (*DeviceSetting, error) {
	var request bytes.Buffer

	fmt.Fprintf(&request, "private_key=%s\n", conf.SecretKey)

	if conf.ListenPort != nil {
		fmt.Fprintf(&request, "listen_port=%d\n", *conf.ListenPort)
	}

	for _, peer := range conf.Peers {
		fmt.Fprintf(&request, heredoc.Doc(`
				public_key=%s
				persistent_keepalive_interval=%d
				preshared_key=%s
			`),
			peer.PublicKey, peer.KeepAlive, peer.PreSharedKey,
		)
		if peer.Endpoint != nil {
			fmt.Fprintf(&request, "endpoint=%s\n", *peer.Endpoint)
		}

		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				fmt.Fprintf(&request, "allowed_ip=%s\n", ip.String())
			}
		} else {
			request.WriteString(heredoc.Doc(`
				allowed_ip=0.0.0.0/0
				allowed_ip=::0/0
			`))
		}
	}

	setting := &DeviceSetting{IpcRequest: request.String(), DNS: conf.DNS, DeviceAddr: conf.Endpoint, MTU: conf.MTU}
	return setting, nil
}

// bindForConfig picks ClientOnlyBind for single-peer configs with a resolved
// endpoint (suppresses the Windows Firewall listener prompt / silent inbound
// block). Falls back to the default bind for multi-peer or endpointless configs.
func bindForConfig(conf *DeviceConfig) conn.Bind {
	if len(conf.Peers) != 1 {
		return conn.NewDefaultBind()
	}
	ep := conf.Peers[0].Endpoint
	if ep == nil {
		return conn.NewDefaultBind()
	}
	ap, err := netip.ParseAddrPort(*ep)
	if err != nil {
		return conn.NewDefaultBind()
	}
	bind, err := clientbind.New(ap)
	if err != nil {
		return conn.NewDefaultBind()
	}
	return bind
}

// StartWireguard creates a tun interface on netstack given a configuration.
//
// Output goes to stdout/stderr at the given level. A caller that needs the log
// lines themselves — to react to them rather than print them — should use
// StartWireguardWithLogger.
func StartWireguard(conf *Configuration, logLevel int) (*VirtualTun, error) {
	return StartWireguardWithLogger(conf, device.NewLogger(logLevel, ""))
}

// StartWireguardWithLogger is StartWireguard with the device's log output
// delivered to the caller instead of written out.
//
// # Why this exists
//
// device.Logger is two function fields, and wireguard-go reports everything
// worth reacting to through them — most importantly:
//
//	"%s - Handshake did not complete after %d seconds, retrying (try %d)"
//
// A tunnel whose credentials have been revoked retries for ever and looks
// exactly like a slow network until you count those lines. A library consumer
// embedding this package has no way to see them otherwise: they go to the
// process's stderr, which in an application is nobody's.
//
// Passing nil silences the device, the same as LogLevelSilent.
func StartWireguardWithLogger(conf *Configuration, logger *device.Logger) (*VirtualTun, error) {
	if logger == nil {
		logger = device.NewLogger(device.LogLevelSilent, "")
	}

	deviceConf := conf.Device
	setting, err := CreateIPCRequest(deviceConf)
	if err != nil {
		return nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN(setting.DeviceAddr, setting.DNS, setting.MTU)
	if err != nil {
		return nil, err
	}
	bind := bindForConfig(deviceConf)
	dev := device.NewDevice(tun, bind, logger)
	err = dev.IpcSet(setting.IpcRequest)
	if err != nil {
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		return nil, err
	}

	hasV4 := false
	hasV6 := false
	for _, addr := range setting.DeviceAddr {
		if addr.Is4() {
			hasV4 = true
		}
		if addr.Is6() {
			hasV6 = true
		}
	}

	if conf.Resolve.ResolveStrategy == "auto" {
		if hasV4 && !hasV6 {
			conf.Resolve.ResolveStrategy = "ipv4"
		} else {
			conf.Resolve.ResolveStrategy = "ipv6"
		}
	}
	return &VirtualTun{
		Tnet:           tnet,
		Dev:            dev,
		Conf:           deviceConf,
		ResolveConfig:  conf.Resolve,
		SystemDNS:      len(setting.DNS) == 0,
		PingRecord:     make(map[string]uint64),
		PingRecordLock: new(sync.Mutex),
	}, nil
}
