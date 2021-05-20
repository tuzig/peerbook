package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	pingPeriod = 5 * time.Second
	// Time allowed to read the next pong message from the peer.
	pongWait = 6 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.

	// Maximum message size allowed from peer.
	maxMessageSize = 4096
	SendBufSize    = 4096
)



type Conn struct {
	WS       *websocket.Conn
	FP       string
	Verified bool
	send     chan []byte
	User     string
}

// readPump pumps messages from the websocket connection to the hub.
//
// The application runs readPump in a per-connection goroutine. The application
// ensures that there is at most one reader on a connection by executing all
// reads from this goroutine.
func (c *Conn) readPump(onDone func()) {
	defer func() {
		hub.unregister <- c
	}()
	c.WS.SetReadLimit(maxMessageSize)
	c.WS.SetReadDeadline(time.Now().Add(pongWait))
	c.WS.SetPongHandler(func(string) error {
		c.WS.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	for {
		message := make(map[string]interface{})
		err := c.WS.ReadJSON(&message)
		if err != nil {
			Logger.Errorf("ws error: %w", err)
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				Logger.Errorf("ws error: %w", err)
			}
			break
		}
		if !c.Verified {
			e := &UnauthorizedPeer{c.FP}
			Logger.Warn(e)
			c.sendStatus(http.StatusUnauthorized, e)
			continue
		}
		message["source_fp"] = c.FP
		// message["user"] = c.User
		c.handleMessage(message)
	}
	onDone()
}

// pinger sends pings
func (c *Conn) pinger() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		hub.unregister <- c
	}()
	Logger.Infof("in pinger")
	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				Logger.Errorf("Got a bad message to send")
				return
			}
			c.WS.SetWriteDeadline(time.Now().Add(writeWait))
			err := c.WS.WriteMessage(websocket.TextMessage, message)
			if err != nil {
				Logger.Warnf("Failed to get websocket writer: %s", err)
				continue
			}
		case <-ticker.C:
			if c.WS == nil {
				break
			}
			c.WS.SetWriteDeadline(time.Now().Add(writeWait))
			err := c.WS.WriteMessage(websocket.PingMessage, nil)
			if err != nil {
				Logger.Errorf("failed to send ping message: %s", err)
				return
			}
		}
	}
	Logger.Infof("out pinger")
}
func (c *Conn) sendStatus(code int, e error) error {
	Logger.Infof("Sending status %d %s", code, e)
	m, err := json.Marshal(StatusMessage{code, e.Error()})
	if err != nil {
		return err
	}
	c.send <- m
	return nil
}

// SendMessage sends a message as json
func SendMessage(tfp string, msg interface{}) error {
	Logger.Infof("publishing message to %q: %v", tfp, msg)
	m, err := json.Marshal(msg)
	rc := db.pool.Get()
	defer rc.Close()
	key := fmt.Sprintf("out:%s", tfp)
	if _, err = rc.Do("PUBLISH", key, m); err != nil {
		return err
	}
	return nil
}

// serveWs handles websocket requests from the peer.
func serveWs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	Logger.Infof("Got a new peer request: %v", q)
	conn, err := ConnFromQ(q)
	if err != nil {
		Logger.Warnf("Refusing a bad request: %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	conn.WS, err = upgrader.Upgrade(w, r, nil)

	if err != nil {
		Logger.Errorf("Failed to upgrade socket: %w", err)
	}
	hub.register <- conn
	go conn.pinger()
	ctx, cancel := context.WithCancel(context.Background())
	go conn.subscribe(ctx)
	go conn.readPump(func() {
		cancel()
	})
	// if it's an unverified peer, keep the connection open and send a status message
	if !conn.Verified {
		err = conn.sendStatus(http.StatusUnauthorized, fmt.Errorf(
			"Unverified peer, please check your inbox to verify"))
		if err != nil {
			Logger.Errorf("Failed to send status message: %s", err)
		}
	}
}

// SetOnline sets the related peer's online redis and notifies peers
func (c *Conn) SetOnline(o bool) error {
	key := fmt.Sprintf("peer:%s", c.FP)
	rc := db.pool.Get()
	defer rc.Close()
	if _, err := rc.Do("HSET", key, "online", o); err != nil {
		return err
	}
	// publish the peer update
	return SendPeerUpdate(rc, c.User, c.FP, c.Verified, o)
}
func SendPeerUpdate(rc redis.Conn, user string, fp string, verified bool, online bool) error {
	m, err := json.Marshal(map[string]interface{}{
		"source_fp":   fp,
		"peer_update": PeerUpdate{Verified: verified, Online: online},
	})
	key := fmt.Sprintf("peers:%s", user)
	if _, err = rc.Do("PUBLISH", key, m); err != nil {
		return err
	}
	return nil
}

func (c *Conn) SendPeerList() error {
	ps, err := GetUsersPeers(c.User)
	if err != nil {
		return err
	}
	m, err := json.Marshal(map[string]interface{}{"peers": ps})
	if err != nil {
		return err
	}
	c.send <- m
	return nil
}

// subscribe listens for messages on Redis pubsub channels. The
func (c *Conn) subscribe(ctx context.Context) {
	// A ping is set to the server with this period to test for the health of
	// the connection and server.
	const healthCheckPeriod = time.Minute
	conn := db.pool.Get()
	defer conn.Close()
	psc := redis.PubSubConn{Conn: conn}
	outK := fmt.Sprintf("out:%s", c.FP)
	peersK := fmt.Sprintf("peers:%s", c.User)
	if err := psc.Subscribe(outK, peersK); err != nil {
		Logger.Errorf("Failed subscribint to our messages: %s", err)
		return
	}

	done := make(chan bool, 1)

	// Start a goroutine to receive notifications from the server.
	go func() {
		for {
			switch n := psc.Receive().(type) {
			case error:
				Logger.Errorf("Receive error from redis: %v", n)
				done <- true
				return
			case redis.Message:
				Logger.Infof("%q got a message: %s", c.FP, n.Data)
				verified, err := IsVerified(c.FP)
				if err != nil {
					Logger.Errorf("Got an error testing if perr verfied: %s", err)
				}
				if verified {
					Logger.Infof("forwarding %q message: %s", c.FP, n.Data)
					c.WS.SetWriteDeadline(time.Now().Add(writeWait))
					c.send <- n.Data
				} else {
					Logger.Infof("ignoring %q message: %s", c.FP, n.Data)
				}
			}
		}
	}()

	ticker := time.NewTicker(healthCheckPeriod)
	defer ticker.Stop()
loop:
	for {
		select {
		case <-ticker.C:
			// Send ping to test health of connection and server. If
			// corresponding pong is not received, then receive on the
			// connection will timeout and the receive goroutine will exit.
			if err := psc.Ping(""); err != nil {
				break loop
			}
		case <-ctx.Done():
			break loop
		case <-done:
			break loop
		}
	}

	// Signal the receiving goroutine to exit by unsubscribing from all channels.
	if err := psc.Unsubscribe(); err != nil {
		Logger.Errorf("Failed to unsubscribe: %s", err)
	}
	<-done
}

// ConnFromQ retruns a fresh Peer based on query paramets: fp, name, kind &
// email
func ConnFromQ(q url.Values) (*Conn, error) {
	fp := q.Get("fp")
	if fp == "" {
		return nil, &PeerNotFound{}
	}
	peer, err := GetPeer(fp)
	if err != nil {
		return nil, err
	}
	if peer == nil {
		return nil, &PeerNotFound{}
	}
	verified, err := IsVerified(fp)
	if err != nil {
		return nil, err
	}

	ret := Conn{FP: fp,
		Verified: verified,
		User:     peer.User,
		send:     make(chan []byte, SendBufSize)}
	return &ret, nil
}

func (c *Conn) handleMessage(m map[string]interface{}) {
	_, offer := m["offer"]
	_, answer := m["answer"]
	_, candidate := m["candidate"]
	if offer || answer || candidate {
		v, found := m["target"]
		if !found {
			Logger.Warnf("Ignoring an forwarding msg with no target")
			return
		}
		tfp := v.(string)
		// verify message is not across users
		rc := db.pool.Get()
		defer rc.Close()
		key := fmt.Sprintf("peer:%s", tfp)
		targetUser, err := redis.String(rc.Do("HGET", key, "user"))
		if err != nil {
			Logger.Errorf("Failed to encode a clients msg: %s", err)
			return
		}
		if c.User != targetUser {
			Logger.Warnf("Refusing to forward across users: %s => %s  ",
				c.User, targetUser)
			c.sendStatus(http.StatusUnauthorized,
				fmt.Errorf("Target peer belongs to user %q", targetUser))
			return
		}

		Logger.Infof("Forwarding: %v", m)
		delete(m, "target")
		SendMessage(tfp, m)
		if err != nil {
			Logger.Errorf("Failed to encode a clients msg: %s", err)
		}
	}
}
