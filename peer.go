// Copyright 2021 Tuzig LTD. All rights reserved.
// based on Gorilla WebSocket.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// Peer is a middleman between the websocket connection and the hub.
type Peer struct {
	hub *Hub
	// The websocket connection.
	ws *websocket.Conn
	// Buffered channel of outbound messages.
	send          chan interface{}
	authenticated bool
}

// PeerDoc is the info we store at redis
type PeerDoc struct {
	user        string
	fingerprint string
	name        string
	kind        string
}

// readPump pumps messages from the websocket connection to the hub.
//
// The application runs readPump in a per-connection goroutine. The application
// ensures that there is at most one reader on a connection by executing all
// reads from this goroutine.
func (p *Peer) readPump() {
	var message map[string]string

	defer func() {
		p.hub.unregister <- p
		p.ws.Close()
	}()
	p.ws.SetReadLimit(maxMessageSize)
	p.ws.SetReadDeadline(time.Now().Add(pongWait))
	p.ws.SetPongHandler(func(string) error { p.ws.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		err := p.ws.ReadJSON(&message)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}
		p.hub.requests <- message
	}
}

// writePump pumps messages from the hub to the websocket connection.
//
// A goroutine running writePump is started for each connection. The
// application ensures that there is at most one writer to a connection by
// executing all writes from this goroutine.
func (p *Peer) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		p.ws.Close()
	}()
	for {
		select {
		case message, ok := <-p.send:
			p.ws.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				p.ws.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			// TODO: add log.Warn before each `continue`
			if err := p.ws.WriteJSON(message); err != nil {
				continue
			}
		case <-ticker.C:
			p.ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := p.ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
func (p *Peer) sendStatus(code int, err error) {
}
func (p *Peer) sendAuthEmail(c *chan bool) {
	*c <- true
}

// serveWs handles websocket requests from the peer.
func serveWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	q := r.URL.Query()
	peer, err := hub.getPeer(hub, conn, q)
	if peer == nil {
		log.Println(err)
		return
	}
	if err != nil {
		_, notFound := err.(*PeerNotFound)
		_, changed := err.(*PeerChanged)
		if notFound || changed {
			peer.sendStatus(401, err)
			var authChan chan bool
			peer.sendAuthEmail(&authChan)
			<-authChan
		}
	}
	// Allow collection of memory referenced by the caller by doing all work in
	// new goroutines.
	go peer.writePump()
	go peer.readPump()
}
