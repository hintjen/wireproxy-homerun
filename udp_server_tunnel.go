package wireproxy

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

type udpServerSession struct {
	localConn  *net.UDPConn
	lastActive time.Time
	closeChan  chan struct{}
}

// Bind resolves the local target and acquires the WireGuard-side listener.
func (conf *UDPServerTunnelConfig) Bind(vt *VirtualTun) error {
	targetAddr, err := net.ResolveUDPAddr("udp", conf.Target)
	if err != nil {
		return fmt.Errorf("udp server tunnel: cannot resolve target %s: %w", conf.Target, err)
	}
	conf.targetAddr = targetAddr

	listener, err := vt.Tnet.ListenUDP(&net.UDPAddr{Port: conf.ListenPort})
	if err != nil {
		return fmt.Errorf(
			"udp server tunnel: cannot listen on WireGuard port %d: %w", conf.ListenPort, err)
	}
	conf.listener = listener
	conf.done = make(chan struct{})
	return nil
}

// Close stops the read loop and the session reaper.
func (conf *UDPServerTunnelConfig) Close() error {
	conf.markClosed()
	if conf.done != nil {
		select {
		case <-conf.done:
		default:
			close(conf.done)
		}
	}
	return closeListener(conf.listener)
}

// Serve forwards each unique source address to the local target over its own
// UDP connection.
// Flow: <WireGuard peer> --(wireguard)--> ListenPort --> Target (local)
func (conf *UDPServerTunnelConfig) Serve(_ *VirtualTun) error {
	if conf.listener == nil {
		return errors.New("udp server tunnel: Serve called before Bind")
	}
	targetAddr := conf.targetAddr
	listener := conf.listener

	log.Printf("UDPServerTunnel listening on WireGuard port %d, forwarding to %s", conf.ListenPort, conf.Target)

	inactivityDur := time.Duration(conf.InactivityTimeout) * time.Second
	sessions := make(map[string]*udpServerSession)
	var mu sync.Mutex

	closeSession := func(key string, sess *udpServerSession) {
		mu.Lock()
		defer mu.Unlock()
		if current, ok := sessions[key]; ok && current == sess {
			select {
			case <-sess.closeChan:
			default:
				close(sess.closeChan)
			}
			delete(sessions, key)
		}
	}

	if conf.InactivityTimeout > 0 {
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-conf.done:
					return
				case <-ticker.C:
				}
				now := time.Now()
				mu.Lock()
				for key, sess := range sessions {
					if now.Sub(sess.lastActive) >= inactivityDur {
						log.Printf("UDPServerTunnel: closing inactive session for %s", key)
						select {
						case <-sess.closeChan:
						default:
							close(sess.closeChan)
						}
						delete(sessions, key)
					}
				}
				mu.Unlock()
			}
		}()
	}

	buf := make([]byte, 64*1024)
	for {
		n, src, err := listener.ReadFrom(buf)
		if err != nil {
			if conf.closedByUs(err) {
				return nil
			}
			errorLogger.Printf("UDPServerTunnel: read from WireGuard error: %v", err)
			continue
		}

		srcAddr, ok := src.(*net.UDPAddr)
		if !ok {
			errorLogger.Printf("UDPServerTunnel: unexpected source address type: %T", src)
			continue
		}
		srcKey := srcAddr.String()

		mu.Lock()
		sess, exists := sessions[srcKey]
		if exists {
			sess.lastActive = time.Now()
		}
		mu.Unlock()

		if !exists {
			localConn, err := net.DialUDP("udp", nil, targetAddr)
			if err != nil {
				errorLogger.Printf("UDPServerTunnel: cannot connect to target %s: %v", conf.Target, err)
				continue
			}

			sess = &udpServerSession{
				localConn:  localConn,
				lastActive: time.Now(),
				closeChan:  make(chan struct{}),
			}

			mu.Lock()
			sessions[srcKey] = sess
			mu.Unlock()

			// Forward responses from local target back to WireGuard peer.
			go func(srcAddr *net.UDPAddr, sess *udpServerSession) {
				defer closeSession(srcAddr.String(), sess)
				defer sess.localConn.Close()

				rbuf := make([]byte, 64*1024)
				for {
					select {
					case <-sess.closeChan:
						return
					default:
					}

					if inactivityDur > 0 {
						_ = sess.localConn.SetReadDeadline(time.Now().Add(5 * time.Second))
					}

					rn, err := sess.localConn.Read(rbuf)
					if err != nil {
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							select {
							case <-sess.closeChan:
								return
							default:
								continue
							}
						}
						errorLogger.Printf("UDPServerTunnel: read from local target error: %v", err)
						return
					}

					mu.Lock()
					sess.lastActive = time.Now()
					mu.Unlock()

					_, err = listener.WriteTo(rbuf[:rn], srcAddr)
					if err != nil {
						errorLogger.Printf("UDPServerTunnel: write to WireGuard peer %s error: %v", srcAddr, err)
						return
					}
				}
			}(srcAddr, sess)
		}

		// Forward the inbound packet to the local target.
		// buf is safe to read here since we haven't called ReadFrom again.
		if _, err = sess.localConn.Write(buf[:n]); err != nil {
			errorLogger.Printf("UDPServerTunnel: write to local target error: %v", err)
		}
	}
}
