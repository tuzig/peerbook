// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/gomodule/redigo/redis"
	"log"
)

// Hub maintains the set of active peers and broadcasts messages to the
// peers.
type Hub struct {
	// Registered peers.
	peers map[string]*Peer

	// Inbound messages from the peers.
	requests chan map[string]string

	// Register requests from the peers.
	register chan *Peer

	// Unregister requests from peers.
	unregister chan *Peer
	redis      redis.Conn
}

func newHub(redisHost string) *Hub {
	conn, err := redis.Dial("tcp", redisHost)
	if err != nil {
		log.Fatal(err)
	}
	return &Hub{
		register:   make(chan *Peer),
		unregister: make(chan *Peer),
		peers:      make(map[string]*Peer),
		redis:      conn,
		requests:   make(chan map[string]string),
	}
}

// forwardSignal Forwards offersa nd answers
func (h *Hub) forwardSignal(m map[string]string) {
	target := m["target"]
	p, found := h.peers[target]
	if !found {
		log.Println("Couldn't find target peer")
	}
	delete(m, "target")
	p.send <- m
}
func (h *Hub) run() {
	for {
		select {
		case peer := <-h.register:
			h.peers[peer.pd.fingerprint] = peer
		case peer := <-h.unregister:
			if _, ok := h.peers[peer.pd.fingerprint]; ok {
				delete(h.peers, peer.pd.fingerprint)
				close(peer.send)
			}
		case message := <-h.requests:
			_, offer := message["offer"]
			_, answer := message["answer"]
			if offer || answer {
				h.forwardSignal(message)
			}
		}
	}
}

func (h *Hub) Close() {
	h.redis.Close()
}
