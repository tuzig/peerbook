package main

import (
	"context"
	"fmt"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/pion/webrtc/v3"
	"github.com/tuzig/webexec/peers"
)

type Connection struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// index is the fingerprint
type ConnectionList map[string]*Connection

var connections = make(ConnectionList)

func (cl ConnectionList) Open(fp string) context.Context {
	if _, ok := cl[fp]; ok {
		cl.Close(fp)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cl[fp] = &Connection{ctx, cancel}
	return ctx
}
func (cl ConnectionList) Close(fp string) {
	cl[fp].cancel()
	delete(cl, fp)
}
func OnConnectionStateChange(webrtcPeer *peers.Peer, state webrtc.PeerConnectionState) {
	switch state {
	case webrtc.PeerConnectionStateConnected:
		// start the sender
		ctx := connections.Open(webrtcPeer.FP)
		go sender(ctx, webrtcPeer.FP, webrtcPeer.SendMessage)
	case webrtc.PeerConnectionStateFailed:
		// stop the sender
		connections.Close(webrtcPeer.FP)
	}
}
func sender(ctx context.Context, fp string, sendFunction func(msg interface{}) error) {
	// A ping is set to the server with this period to test for the health of
	// the connection and server.
	const healthCheckPeriod = time.Minute
	conn := db.pool.Get()
	defer conn.Close()
	psc := redis.PubSubConn{Conn: conn}
	defer psc.Unsubscribe()
	outK := fmt.Sprintf("out:%s", fp)
	if err := psc.Subscribe(outK); err != nil {
		Logger.Errorf("Failed subscribint to our messages: %s", err)
		return
	}

	ticker := time.NewTicker(healthCheckPeriod)
	defer ticker.Stop()
	// Start a goroutine to receive notifications from the server.
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-ticker.C:
			// Send ping to test health of connection and server. If
			// corresponding pong is not received, then receive on the
			// connection will timeout and the receive goroutine will exit.
			if err := psc.Ping(""); err != nil {
				Logger.Warnf("Redis PubSub Pong timeout: %s", err)
				break loop
			}
		default:
			switch n := psc.Receive().(type) {
			case error:
				Logger.Errorf("Receive error from redis: %v", n)
				break loop
			case redis.Message:
				verified, err := IsVerified(fp)
				if err != nil {
					Logger.Errorf("Got an error testing if perr verfied: %s", err)
					return
				}
				if verified {
					Logger.Infof("forwarding %q message: %s", fp, n.Data)
					sendFunction(string(n.Data))
				} else {
					Logger.Infof("ignoring %q message: %s", fp, n.Data)
				}
			}
		}
	}
}
