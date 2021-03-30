// Copyright 2021 Tuzig LTD. All rights reserved.
// based on Gorilla WebSocket.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/gorilla/websocket"
	"net/http"
	"net/url"
	"time"
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
	DBPeer
	// The websocket connection.
	ws *websocket.Conn
	// Buffered channel of outbound messages.
	authenticated bool
}

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

func newPeer(q url.Values) (*Peer, error) {
	fp := q.Get("fp")
	if fp == "" {
		return nil, fmt.Errorf("Missing `fp` query parameter")
	}
	exists, err := db.PeerExists(fp)
	if err != nil {
		return nil, err
	}
	peer := Peer{}
	peer.FP = fp
	if !exists {
		return &peer, &PeerNotFound{}
	}
	pd, err := db.GetPeer(fp)

	// same fingerprint changed details. could be the hostname changed,
	// return un authenticated peer and a the `PeerChanged` error
	if pd.Name != q.Get("name") ||
		pd.User != q.Get("user") ||
		pd.Kind != q.Get("kind") {
		return &peer, &PeerChanged{}
	}
	// copy all the data from redis
	peer.User = pd.User
	peer.Name = pd.Name
	peer.Kind = pd.Kind
	peer.authenticated = true
	return &peer, nil
}

// readPump pumps messages from the websocket connection to the hub.
//
// The application runs readPump in a per-connection goroutine. The application
// ensures that there is at most one reader on a connection by executing all
// reads from this goroutine.
func (p *Peer) readPump() {
	var message map[string]string

	defer func() {
		hub.unregister <- p
		p.ws.Close()
	}()
	p.ws.SetReadLimit(maxMessageSize)
	p.ws.SetReadDeadline(time.Now().Add(pongWait))
	p.ws.SetPongHandler(func(string) error { p.ws.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		err := p.ws.ReadJSON(&message)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				Logger.Errorf("error: %v", err)
			}
			break
		}
		message["source"] = p.FP
		hub.requests <- message
	}
}

// pinger sends pings
func (p *Peer) pinger() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		p.ws.Close()
	}()
	for {
		select {
		case <-ticker.C:
			p.Send(websocket.PingMessage)
		}
	}
}
func (p *Peer) sendStatus(code int, e error) error {
	msg := StatusMessage{code, e.Error()}
	return p.Send(msg)
}

// Send send a message as json
func (p *Peer) Send(msg interface{}) error {
	p.ws.SetWriteDeadline(time.Now().Add(writeWait))
	if err := p.ws.WriteJSON(msg); err != nil {
		return fmt.Errorf("failed to send status message: %w", err)
	}
	return nil
}
func (p *Peer) sendAuthEmail() error {
	// TODO: send an email in the background, the email should havssss
	return nil
}

// Upgrade upgrade an http request to a websocket and stores it
func (p *Peer) Upgrade(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		Logger.Errorf("Failed to upgrade socket: %w", err)
	}
	p.ws = conn
}

func (p *Peer) sendList() error {
	l, err := db.GetUserPeers(p.User)
	if err != nil {
		return err
	}
	return p.Send(l)
}

// serveWs handles websocket requests from the peer.
func serveWs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	Logger.Info("Got a new peer request")
	peer, err := newPeer(q)
	if peer == nil {
		msg := fmt.Sprintf("Failed to create a new peer: %s", err)
		Logger.Warn(msg)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hub.register <- peer
	if err != nil {
		_, notFound := err.(*PeerNotFound)
		_, changed := err.(*PeerChanged)
		if notFound || changed {
			peer.Upgrade(w, r)
			peer.sendStatus(401, err)
			err = peer.sendAuthEmail()
			if err != nil {
				Logger.Errorf("Failed to send an auth email: %w", err)
			}
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		peer.Upgrade(w, r)
	}
	// Allow collection of memory referenced by the caller by doing all work in
	// new goroutines.
	go peer.pinger()
	go peer.readPump()
}
