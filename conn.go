package main

import (
	"fmt"
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
func (c *Conn) readPump() {
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
}

// pinger sends pings
func (c *Conn) pinger() {
	errRun := 0
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
				errRun++
				if errRun == 3 {
					return
				}
			} else {
				errRun = 0
			}
		}
	}
	Logger.Infof("out pinger")
}
func (c *Conn) sendStatus(code int, e error) error {
	Logger.Infof("Sending status %d %s", code, e)
	msg := StatusMessage{code, e.Error()}
	return c.Send(msg)
}

// Send send a message as json
func (c *Conn) Send(msg interface{}) error {
	if c.WS == nil {
		return fmt.Errorf("trying to send a message to closed websocket: %v", msg)
	}
	c.send <- msg
	Logger.Infof("Added a message to send, it's size: %d", len(c.send))
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
	go conn.readPump()
	go conn.pinger()
	// if it's an unverified peer, keep the connection open and send a status message
	if !conn.Verified {
		err = conn.sendStatus(401, fmt.Errorf(
			"Unverified peer, please check your inbox to verify"))
		if err != nil {
			Logger.Errorf("Failed to send status message: %s", err)
		}
	}
}

// SetOnline sets the related peer's online redis cache and notifies peers
func (c *Conn) SetOnline(o bool) error {
	key := fmt.Sprintf("peer:%s", c.FP)
	rc := db.pool.Get()
	defer rc.Close()
	if _, err := rc.Do("HSET", key, "online", o); err != nil {
		return err
	}
	return nil
}
