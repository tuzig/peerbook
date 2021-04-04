// Copyright 2021 Tuzig LTD. All rights reserved.
// based on Gorilla WebSocket.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = 50 * time.Second

	// Maximum message size allowed from peer.
	maxMessageSize = 4096
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  maxMessageSize,
	WriteBufferSize: maxMessageSize,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// Peer is a middleman between the websocket connection and the hub.
type Peer struct {
	DBPeer
	// The websocket connection.
	ws *websocket.Conn
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

// PeerFromQ retruns a fresh Peer based on query paramets: fp, name, kind &
// email
func PeerFromQ(q url.Values) (*Peer, error) {
	fp := q.Get("fp")
	if fp == "" {
		return nil, fmt.Errorf("Missing `fp` query parameter")
	}
	return &Peer{DBPeer{FP: fp, Name: q.Get("name"), Kind: q.Get("kind"),
		User: q.Get("email"), Verified: false}, nil}, nil
}

// LoadPeer loads a peer from redis based on a given peer
func LoadPeer(baseP *Peer) (*Peer, error) {
	peer, found := hub.peers[baseP.FP]
	if found {
		return peer, nil
	}
	exists, err := db.PeerExists(baseP.FP)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, &PeerNotFound{}
	}
	var p Peer
	key := fmt.Sprintf("peer:%s", baseP.FP)
	db.getDoc(key, &p)
	// ensure the same details
	if p.Name != baseP.Name ||
		p.User != baseP.User ||
		p.Kind != baseP.Kind {
		return nil, &PeerChanged{}
	}
	return &p, nil
}

// readPump pumps messages from the websocket connection to the hub.
//
// The application runs readPump in a per-connection goroutine. The application
// ensures that there is at most one reader on a connection by executing all
// reads from this goroutine.
func (p *Peer) readPump() {

	defer func() {
		hub.unregister <- p
		p.ws.Close()
	}()
	p.ws.SetReadLimit(maxMessageSize)
	p.ws.SetReadDeadline(time.Now().Add(pongWait))
	p.ws.SetPongHandler(func(string) error { p.ws.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		var message map[string]interface{}
		err := p.ws.ReadJSON(&message)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				Logger.Errorf("ws error: %w", err)
			}
			break
		}
		// TODO: do we use the "source" ?
		message["source"] = p.FP
		hub.requests <- message
	}
}

// pinger sends pings
func (p *Peer) pinger() {
	errRun := 0
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		// p.ws.Close()
	}()
	for {
		select {
		case <-ticker.C:
			err := p.ws.WriteMessage(websocket.PingMessage, nil)
			if err != nil {
				Logger.Errorf("failed to send ping message: %w", err)
				errRun++
				if errRun == 3 {
					return
				}

			} else {
				errRun = 0
			}
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
	return p.Send(map[string]*DBPeerList{"peers": l})
}

// serveWs handles websocket requests from the peer.
func serveWs(w http.ResponseWriter, r *http.Request) {
	var notFound bool
	q := r.URL.Query()
	Logger.Infof("Got a new peer request: %v", q)
	qp, err := PeerFromQ(q)
	if err != nil {
		msg := fmt.Sprintf("Bad peer requested: %s", err)
		Logger.Warn(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	peer, err := LoadPeer(qp)
	if err != nil {
		_, notFound = err.(*PeerNotFound)
		_, changed := err.(*PeerChanged)
		if changed {
			msg := fmt.Sprintf("Request from a weird peer: %s", err)
			Logger.Warn(msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		if notFound {
			Logger.Infof("Peer not found")
			// rollback - work with the unverified peer from the query
			peer = qp
			err = peer.sendAuthEmail()
			if err != nil {
				Logger.Errorf("Failed to send an auth email: %w", err)
			}
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	peer.Upgrade(w, r)
	hub.register <- peer
	go peer.pinger()
	go peer.readPump()
	// if it's an unknow peer, keep the connection open and send a status message
	if notFound {
		peer.sendStatus(401, fmt.Errorf("Unknown peer. To approve please check your email inbox."))
	}
}
