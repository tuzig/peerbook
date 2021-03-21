// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/gomodule/redigo/redis"
	"github.com/gorilla/websocket"
	"log"
	"net/url"
)

// Hub maintains the set of active peers and broadcasts messages to the
// peers.
type Hub struct {
	// Registered peers.
	peers map[*Peer]bool

	// Inbound messages from the peers.
	requests chan map[string]string

	// Register requests from the peers.
	register chan *Peer

	// Unregister requests from peers.
	unregister chan *Peer
	redis      redis.Conn
}

func newHub() *Hub {
	conn, err := redis.Dial("tcp", "localhost:6379")
	if err != nil {
		log.Fatal(err)
	}
	return &Hub{
		register:   make(chan *Peer),
		unregister: make(chan *Peer),
		peers:      make(map[*Peer]bool),
		redis:      conn,
		requests:   make(chan map[string]string),
	}
}

func (h *Hub) handleAnswer(m map[string]string) {
}
func (h *Hub) handleOffer(m map[string]string) {
}
func (h *Hub) run() {
	for {
		select {
		case peer := <-h.register:
			h.peers[peer] = true
		case peer := <-h.unregister:
			if _, ok := h.peers[peer]; ok {
				delete(h.peers, peer)
				// close(peer.send)
			}
		case message := <-h.requests:
			if _, found := message["offer"]; found {
				h.handleOffer(message)
			} else if _, found := message["answer"]; found {
				h.handleAnswer(message)
			}
		}
	}
}

func (h *Hub) getPeer(hub *Hub, ws *websocket.Conn, q url.Values) (*Peer, error) {
	var pd PeerDoc
	key := fmt.Sprintf("peer:%s", q.Get("fingerprint"))
	exists, err := redis.Bool(h.redis.Do("EXISTS", key))
	if err != nil {
		return nil, err
	}
	peer := Peer{hub: hub, ws: ws, send: make(chan interface{}, 8), authenticated: false}
	if !exists {
		return &peer, &PeerNotFound{}
	}
	values, err := redis.Values(h.redis.Do("HGETALL", key))
	if err = redis.ScanStruct(values, &pd); err != nil {
		return nil, fmt.Errorf("Failed to scan peer %q: %w", key, err)
	}
	if pd.name != q.Get("name") ||
		pd.user != q.Get("user") ||
		pd.kind != q.Get("kind") {
		return &peer, &PeerChanged{}
	}
	peer.authenticated = true
	return &peer, nil
}
func (h *Hub) Close() {
	h.redis.Close()
}
