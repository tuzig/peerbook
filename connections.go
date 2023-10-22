package main

import (
	"context"
	"encoding/json"
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
func OnPeerMsg(webrtcPeer *peers.Peer, msg webrtc.DataChannelMessage) {
	// TODO: handle incoming messages
	var raw json.RawMessage
	var body []byte
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
			body, err = register(fp, args.Email, args.PeerName)
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
			Target string `json:"target"`
			SDP    string `json:"sdp"`
		}
		err = json.Unmarshal(raw, &args)
		if err == nil {
			err = forwardSDP(fp, args.Target, "offer", args.SDP)
		}
	case "candidate":
		var args struct {
			Target string `json:"target"`
			SDP    string `json:"sdp"`
		}
		err = json.Unmarshal(raw, &args)
		if err == nil {
			err = forwardSDP(fp, args.Target, "candidate", args.SDP)
		}
		/* TODO
		case "answer":
		*/
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
