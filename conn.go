package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait  = 10 * time.Second
	pingPeriod = 50 * time.Second
	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second
	// Maximum message size allowed from peer.
	maxMessageSize = 4096
	SendBufSize    = 4096
)

type Conn struct {
	WS         *websocket.Conn
	FP         string
	Verified   bool
	UserActive bool
	send       chan []byte
	User       string
	Kind       string
	Name       string
}

// PeerUpdate is a struct for peer update messages
type PeerUpdate struct {
	Verified bool   `redis:"verified" json:"verified"`
	Online   bool   `redis:"online" json:"online"`
	Name     string `redis:"name" json:"name"`
	// TODO: should we add the authorization token?
}

// readPump pumps messages from the websocket connection to the hub.
//
// The application runs readPump in a per-connection goroutine. The application
// ensures that there is at most one reader on a connection by executing all
// reads from this goroutine.
func (c *Conn) readPump() {
	c.WS.SetReadLimit(maxMessageSize)
	c.WS.SetReadDeadline(time.Now().Add(pongWait))
	c.WS.SetPongHandler(func(string) error {
		c.WS.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.subscribe(ctx)
	go c.sender(ctx)
	for {
		message := make(map[string]interface{})
		err := c.WS.ReadJSON(&message)
		if err != nil {
			Logger.Info("Exiting read pump for %q on error: %s", c.FP, err)
			break
		}
		verified, err := IsVerified(c.FP)
		if err != nil {
			Logger.Warnf("Failed to test if peer verified: %s", err)
		}
		if !verified && c.Verified {
			e := &UnauthorizedPeer{c.FP}
			Logger.Warn(e)
			c.sendStatus(http.StatusUnauthorized, e)
			continue
		}
		message["source_fp"] = c.FP
		// message["user"] = c.User
		c.handleMessage(message)
	}
}

// sender sends messages and pings
func (c *Conn) sender(ctx context.Context) {
	ticker := time.NewTicker(pingPeriod)
loop:
	for {
		select {
		case message, ok := <-c.send:
			Logger.Infof("Got a message to send: %s", message)
			if !ok {
				Logger.Errorf("Got a bad message to send")
				continue
			}
			c.WS.SetWriteDeadline(time.Now().Add(writeWait))
			err := c.WS.WriteMessage(websocket.TextMessage, message)
			if err != nil {
				if websocket.IsUnexpectedCloseError(err,
					websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					Logger.Warnf("Failed to send websocket message: %s", err)
					return
				}
				continue
			}
		case <-ticker.C:
			if c.WS == nil {
				Logger.Info("Breaking on nil WS")
				break loop
			}
			c.WS.SetWriteDeadline(time.Now().Add(writeWait))
			err := c.WS.WriteMessage(websocket.PingMessage, nil)
			if err != nil {
				if websocket.IsUnexpectedCloseError(err,
					websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					Logger.Errorf("failed to send ping message: %s", err)
				}
				return
			}
		case <-ctx.Done():
			Logger.Infof("Exiting sender for %q", c.FP)
			break loop
		}
	}
	ticker.Stop()
	hub.unregister <- c
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
	rcURL := os.Getenv("REVENUECAT_URL")
	if rcURL == "" {
		rcURL = "https://api.revenuecat.com"
	}
	conn, err := ConnFromQ(q, rcURL)
	if err != nil {
		Logger.Errorf("Failed creating a Conn: %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	conn.WS, err = upgrader.Upgrade(w, r, nil)

	if err != nil {
		Logger.Errorf("Failed to upgrade socket: %w", err)
		return
	}
	go conn.readPump()
	// if it's an unverified peer, keep the connection open and send a status message
	hub.register <- conn
}

func (c *Conn) Welcome() {
	if c.Verified && c.UserActive {
		c.SendPeerList()
	} else {
		msg := fmt.Errorf(
			"Unverified peer, please use Terminal7 to verify or at https://peerbook.io")
		if c.UserActive {
			msg = fmt.Errorf("Subscription inactive, please use Terminal7 to renew your subscription")
		}
		err := c.sendStatus(http.StatusUnauthorized, msg)
		if err != nil {
			Logger.Errorf("Failed to send status message: %s", err)
		}
	}

	if err := c.SetOnline(true); err != nil {
		Logger.Errorf("Failed setting a peer as online: %s", err)
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
	return SendPeerUpdate(rc, c.User, c.FP, c.Verified, o, c.Name)
}

func SendPeerUpdate(rc redis.Conn, user string, fp string, verified bool, online bool, name string) error {
	m, err := json.Marshal(map[string]interface{}{
		"source_fp":   fp,
		"peer_update": PeerUpdate{Verified: verified, Online: online, Name: name},
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
		return fmt.Errorf("Failed to get peer list: %w", err)
	}

	msg := map[string]interface{}{"uid": c.User}
	if ps != nil && len(*ps) > 0 {
		msg["peers"] = ps
	} else {
		msg["peers"] = []string{}
	}
	var m []byte
	m, err = json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("Failed to marshal peer list: %w", err)
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
	defer psc.Unsubscribe()
	outK := fmt.Sprintf("out:%s", c.FP)
	peersK := fmt.Sprintf("peers:%s", c.User)
	if err := psc.Subscribe(outK, peersK); err != nil {
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
				Logger.Info("Pong timeout")
				break loop
			}
		default:
			switch n := psc.Receive().(type) {
			case error:
				Logger.Errorf("Receive error from redis: %v", n)
				break loop
			case redis.Message:
				verified, err := IsVerified(c.FP)
				if err != nil {
					Logger.Errorf("Got an error testing if perr verfied: %s", err)
					return
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
	}
}

// ConnFromQ gets a a url values and returns a pointer to Conn
//
//		It first looks for an existing peer based on the fingerprint.
//	 If found, it will reconcile the input fields and throw errors.
//	 If it's a fresh peer it will be added to the database.
func ConnFromQ(q url.Values, rcURL string) (*Conn, error) {
	fp := q.Get("fp")
	name := q.Get("name")
	uid := q.Get("uid")
	kind := q.Get("kind")
	if fp == "" {
		return nil, &PeerNotFound{}
	}
	peer, err := GetPeer(fp)
	if err != nil {
		return nil, fmt.Errorf("Failed to get peer: %w", err)
	}
	// FP can be empty because of redisDouble used in testing
	if peer == nil || peer.FP == "" {
		peer = NewPeer(fp, name, uid, kind)
		err = db.AddPeer(peer)
		if err != nil {
			return nil, fmt.Errorf("Failed to add peer: %s", err)
		}
	} else {
		// field validation & sync
		if name != "" && peer.Name != name {
			peer.setName(name)
		}
		if peer.User == "" {
			return nil, fmt.Errorf("Peer user id empty %v", peer)
			/*
				Logger.Warn("peer user id empty")
				peer = NewPeer(fp, name, uid, kind)
				err = db.AddPeer(peer)
				if err != nil {
					return nil, fmt.Errorf("Failed to add peer: %s", err)
				}
			*/
		} else {
			active, err := isUIDActive(peer.User, rcURL)
			if err != nil {
				return nil, fmt.Errorf("Failed to check if uid active: %s", err)
			}
			if !active {
				return nil, fmt.Errorf("UID %s not active", peer.User)
			}
		}
	}
	return NewConn(peer, rcURL)
}
func NewConn(peer *Peer, rcURL string) (*Conn, error) {
	verified := peer.Verified
	userActive := false
	if rcURL != "" && verified {
		var err error
		userActive, err = isUIDActive(peer.User, rcURL)
		if err != nil {
			return nil, fmt.Errorf("Failed to check if uid active: %s", err)
		}
	}

	c := &Conn{FP: peer.FP,
		Verified:   verified,
		User:       peer.User,
		send:       make(chan []byte, SendBufSize),
		UserActive: userActive,
		Kind:       peer.Kind,
		Name:       peer.Name,
	}
	return c, nil
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
		rc.Do("HSET", key, "last_connect", time.Now().Unix())
		delete(m, "target")
		SendMessage(tfp, m)
	}
}
