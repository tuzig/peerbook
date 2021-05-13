package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gomodule/redigo/redis"
	"github.com/gorilla/websocket"
	"net/http"
	"time"
)

type Conn struct {
	WS       *websocket.Conn
	FP       string
	Verified bool
	send     chan interface{}
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
		var message map[string]interface{}
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
		message["user"] = c.User
		hub.requests <- message
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
			Logger.Infof("sending message: %v", message)
			c.WS.SetWriteDeadline(time.Now().Add(writeWait))
			err := c.WS.WriteJSON(message)
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
	msg := StatusMessage{code, e.Error()}
	return SendMessage(c.FP, msg)
}

// SendMessage sends a message as json
func SendMessage(tfp string, msg interface{}) error {
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
		err = conn.sendStatus(402, fmt.Errorf(
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
	// publish the peers state
	key = fmt.Sprintf("peers:%s", c.User)
	msg := PeerUpdate{c.FP, c.Verified, o}
	m, err := json.Marshal(msg)
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
	return SendMessage(c.FP, map[string]interface{}{"peers": ps})
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
				c.WS.SetWriteDeadline(time.Now().Add(writeWait))
				err := c.WS.WriteMessage(websocket.TextMessage, n.Data)
				if err != nil {
					Logger.Warnf("Failed to write websocket msg: %s", err)
					done <- true
					return
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
