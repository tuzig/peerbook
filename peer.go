// Copyright 2021 TUZIG LTD and peerbook Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 6 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = 5 * time.Second

	// Maximum message size allowed from peer.
	maxMessageSize = 4096
	DefaultHomeUrl = "https://pb.terminal7.dev"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  maxMessageSize,
	WriteBufferSize: maxMessageSize,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

type Conn struct {
	WS       *websocket.Conn
	FP       string
	Verified bool
	send     chan interface{}
	User     string
}

// Peer is a middleman between the websocket connection and the hub.
type Peer struct {
	FP          string `redis:"fp" json:"fp"`
	Name        string `redis:"name" json:"name,omitempty"`
	User        string `redis:"user" json:"user,omitempty"`
	Kind        string `redis:"kind" json:"kind,omitempty"`
	Verified    bool   `redis:"verified" json:"verified,omitempty"`
	CreatedOn   int64  `redis:"created_on" json:"created_on,omitempty"`
	VerifiedOn  int64  `redis:"verified_on" json:"verified_on,omitempty"`
	LastConnect int64  `redis:"last_connect" json:"last_connect,omitempty"`
	Online      bool   `redis:"online" json:"online"`
}
type PeerList []*Peer

// StatusMessage is used to update the peer to a change of state,
// like 200 after the peer has been authorized
type StatusMessage struct {
	Code int    `json:"code"`
	Text string `json:"text"`
}

// OfferMessage is the format of the offer message after processing -
// including the source_name & source_fp read from the db
type OfferMessage struct {
	SourceName string `json:"source_name"`
	SourceFP   string `json:"source_fp"`
	Offer      string `json:"offer"`
}

// AnswerMessage is the format of the answer message after processing -
// including the source_name & source_fp read from the db
type AnswerMessage struct {
	SourceName string `json:"source_name"`
	SourceFP   string `json:"source_fp"`
	Answer     string `json:"answer"`
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
	c.WS.SetPongHandler(func(string) error {
		c.WS.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	for {
		var message map[string]interface{}
		c.WS.SetReadDeadline(time.Now().Add(pongWait))
		err := c.WS.ReadJSON(&message)
		if err != nil {
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
	go conn.pinger()
	go conn.readPump()
	// if it's an unverified peer, keep the connection open and send a status message
	if !conn.Verified {
		err = conn.sendStatus(401, fmt.Errorf(
			"Unverified peer, please check your inbox to verify"))
		if err != nil {
			Logger.Errorf("Failed to send status message: %s", err)
		}
	}
}

// Getting the list of users peers
func GetUsersPeers(email string) (*PeerList, error) {
	var l PeerList
	u, err := db.GetUser(email)
	if err != nil {
		return nil, err
	}
	// TODO: use redis transaction to read them all at once
	for _, fp := range *u {
		p, err := GetPeer(fp)
		if err != nil {
			Logger.Warnf("Failed to read peer: %w", err)
			if err != nil {
				Logger.Errorf("Failed to send status message: %s", err)
			}
		} else {
			l = append(l, p)
		}
	}
	return &l, nil
}

func (p *Peer) setName(name string) {
	key := fmt.Sprintf("peer:%s", p.FP)
	p.Name = name
	conn := db.pool.Get()
	defer conn.Close()
	conn.Do("HSET", key, "name", name)
}
