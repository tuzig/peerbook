package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/pion/webrtc/v3"
	"github.com/tuzig/webexec/peers"
)

type Connection struct {
	llPeer *peers.Peer
	cancel context.CancelFunc
}

// index is the fingerprint
type ConnectionList struct {
	sync.Mutex
	conns map[string]*Connection
}

var connections ConnectionList = ConnectionList{conns: make(map[string]*Connection)}

func (c *Connection) sendPeerList() error {
	Logger.Infof("Sending peer list to %q", c.llPeer.FP)
	uID, err := db.GetUID4FP(c.llPeer.FP)
	if err != nil {
		return fmt.Errorf("Failed to get uid - %s", err)
	}
	m, err := GetPeersMessage(uID)
	if err != nil {
		return fmt.Errorf("Failed to get peers message - %s", err)
	}
	msg, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("Failed to marshal peers message - %s", err)
	}
	err = c.llPeer.SendMessage(msg)
	if err != nil {
		Logger.Errorf("Failed to send peers message - %s", err)
	}
	return nil
}
func (c *Connection) sendIceServers() error {
	servers, err := GetICEServers()
	// return the JSON representation of the servers
	if err != nil {
		return fmt.Errorf("Failed to get ice servers: %s", err)
	}
	msg := map[string]interface{}{"ice_servers": servers}
	b, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("Failed to marshal ice servers: %s", err)
	}
	c.llPeer.SendMessage(b)
	return nil
}

// Welcome sends a welcome message over the connection
func (c *Connection) Welcome() {
	Logger.Debugf("Welcoming peer %q", c.llPeer.FP)
	err := c.sendPeerList()
	if err != nil {
		Logger.Errorf("Failed to send peer list: %s", err)
	}
	err = c.sendIceServers()
	if err != nil {
		Logger.Errorf("Failed to send ice servers: %s", err)
	}
}

func (cl *ConnectionList) Get(fp string) (*Connection, bool) {
	cl.Lock()
	defer cl.Unlock()
	c, ok := cl.conns[fp]
	return c, ok
}

// ConnectionList.Start starts the sender for the given peer
func (cl *ConnectionList) Start(webrtcPeer *peers.Peer) {
	fp := webrtcPeer.FP
	cl.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	cl.conns[fp] = &Connection{llPeer: webrtcPeer, cancel: cancel}
	cl.Unlock()
	go func() {
		defer webrtcPeer.Close()
		Logger.Debugf("Starting sender for %q", fp)
		sender(ctx, webrtcPeer.FP, webrtcPeer.SendMessage)
		Logger.Debugf("Sender for %q exited", fp)
	}()

}

// Stop stops the sender for the given peer
func (cl *ConnectionList) Stop(webrtcPeer *peers.Peer) {
	cl.Lock()
	defer cl.Unlock()
	if conn, ok := cl.conns[webrtcPeer.FP]; ok {
		conn.cancel()
		delete(cl.conns, webrtcPeer.FP)
	}
}

// Stop stops the sender for the given peer
func (cl *ConnectionList) StopAll() {
	cl.Lock()
	defer cl.Unlock()
	for _, conn := range cl.conns {
		conn.cancel()
	}
	cl.conns = make(map[string]*Connection)
}
func OnConnectionStateChange(webrtcPeer *peers.Peer, state webrtc.PeerConnectionState) {
	switch state {
	case webrtc.PeerConnectionStateConnected:
		// start the sender
		connections.Start(webrtcPeer)
	case webrtc.PeerConnectionStateFailed:
		// stop the sender
		connections.Stop(webrtcPeer)
	}
}
func sender(ctx context.Context, fp string, sendFunction func(msg []byte) error) {
	// A ping is set to the server with this period to test for the health of
	// the connection and server.
	const healthCheckPeriod = time.Minute
	var psc redis.PubSubConn
	conn := db.pool.Get()
	defer conn.Close()
	keys := []string{fmt.Sprintf("out:%s", fp)}
	uid, err := db.GetUID4FP(fp)
	if err != nil {
		Logger.Errorf("Failed to get uid for %q: %s", fp, err)
	} else {
		if uid != "" && uid != "TBD" {
			keys = append(keys, fmt.Sprintf("usercast:%s", uid))
		}
	}
	ticker := time.NewTicker(healthCheckPeriod)
	defer ticker.Stop()
sub:
	psc = redis.PubSubConn{Conn: conn}
	defer psc.Unsubscribe()
	if err := psc.Subscribe(redis.Args{}.AddFlat(keys)...); err != nil {
		// if err := psc.Subscribe(outK); err != nil {
		Logger.Errorf("Failed to subscribe to redis messages: %s", err)
		return
	}

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
			go func() {
				if err := psc.Ping(""); err != nil {
					Logger.Warnf("Redis PubSub Pong timeout: %s", err)
				}
			}()
		default:
			switch n := psc.Receive().(type) {
			case error:
				Logger.Errorf("Receive error from redis: %v, retrying", n)
				psc.Unsubscribe()
				goto sub
			case redis.Message:
				if IsVerified(fp) {
					Logger.Infof("forwarding %q message: %s", fp, n.Data)
					sendFunction(n.Data)
				} else {
					Logger.Infof("ignoring %q message: %s", fp, n.Data)
				}
			}
		}
	}
}
func OnPeerMsg(webrtcPeer *peers.Peer, msg webrtc.DataChannelMessage) {
	if msg.Data == nil {
		verified := IsVerified(webrtcPeer.FP)
		Logger.Debugf("Got a nil message, verified: %v", verified)
		if verified {
			conn, ok := connections.Get(webrtcPeer.FP)
			if !ok {
				Logger.Errorf("Failed to get connection for %q", webrtcPeer.FP)
				return
			}
			go conn.Welcome()
		}
		return
	}
	var raw json.RawMessage
	var body string
	fp := webrtcPeer.FP
	m := peers.CTRLMessage{
		Args: &raw,
	}
	Logger.Infof("Got a CTRLMessage: %q\n", string(msg.Data))
	err := json.Unmarshal(msg.Data, &m)
	if err != nil {
		webrtcPeer.SendNack(m, fmt.Sprintf("Failed to parse incoming control message: %v", err))
		return
	}
	switch m.Type {
	case "delete":
		var args struct {
			Target string `json:"target"`
			OTP    string `json:"otp"`
		}
		err = json.Unmarshal(raw, &args)
		if err == nil {
			err = deletePeer(fp, args.Target, args.OTP)
		}
	case "register":
		var args struct {
			Email    string `json:"email"`
			PeerName string `json:"peer_name"`
		}
		err = json.Unmarshal(raw, &args)
		if err == nil {
			reply, err := register(fp, args.Email, args.PeerName)
			// marshal the message to send it back
			if err == nil {
				var resp []byte
				resp, err = json.Marshal(reply)
				body = string(resp)
			}
		}
	case "rename":
		var args struct {
			Target string `json:"target"`
			Name   string `json:"name"`
		}
		err = json.Unmarshal(raw, &args)
		if err == nil {
			err = rename(fp, args.Target, args.Name)
		}
	case "verify":
		var args struct {
			Target string `json:"target"`
			OTP    string `json:"otp"`
		}
		Logger.Debug("verifying peer")
		err = json.Unmarshal(raw, &args)
		if err == nil {
			err = verify(fp, args.Target, args.OTP)
		}
		tPeer, ok := connections.Get(args.Target)
		if ok {
			go tPeer.sendPeerList()
		}
	case "ping":
		// ping can be used to check if the server is alive
		// if given an argument, it assumes it'n an OTP and will
		// check it against the user's secret and will echo 0 if it's
		// valid and 1 if it's not
		var args struct {
			OTP string `json:"otp"`
		}
		err = json.Unmarshal(raw, &args)
		if err == nil {
			body, err = ping(fp, args.OTP)
		} else {
			body, err = ping(fp, "")
		}
	case "offer":
		var args struct {
			Target string          `json:"target"`
			SDP    json.RawMessage `json:"sdp"`
		}
		err = json.Unmarshal(raw, &args)
		if err == nil {
			err = forwardSDP(fp, args.Target, "offer", args.SDP)
		}
	case "candidate":
		var args struct {
			Target string          `json:"target"`
			SDP    json.RawMessage `json:"sdp"`
		}
		err = json.Unmarshal(raw, &args)
		if err == nil {
			err = forwardSDP(fp, args.Target, "candidate", args.SDP)
		}
		/* TODO
		case "answer":
		*/
	case "ice_servers":
		servers, err := GetICEServers()
		if err != nil {
			Logger.Errorf("Failed to get ice servers: %s", err)
			return
		}
		Logger.Infof("Sending ice servers: %v", servers)
		resp, err := json.Marshal(servers)
		if err != nil {
			Logger.Errorf("Failed to marshal ice servers: %s", err)
		}
		body = string(resp)
	}
	if err != nil {
		Logger.Infof("Sending NACK: %v", body)
		err = webrtcPeer.SendNack(m, err.Error())
	} else {
		Logger.Infof("Sending ACK: %v", body)
		err = webrtcPeer.SendAck(m, body)
	}
	if err != nil {
		Logger.Errorf("Failed to send ACK/NACK: %v", err)
	}
}
