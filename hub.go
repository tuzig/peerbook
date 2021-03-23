// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/gomodule/redigo/redis"
	"log"
	"net/http"
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
		requests:   make(chan map[string]string, 16),
	}
}

// forwardSignal Forwards offers and answers after it ensures the peer is known
// and is authenticated
func (h *Hub) forwardSignal(s *Peer, m map[string]string) {
	target := m["target"]
	p, found := h.peers[target]
	if !found {
		e := &TargetNotFound{target}
		Logger.Warn(e)
		s.sendStatus(http.StatusBadRequest, e)
		return
	}
	if !p.authenticated {
		e := &UnauthorizedPeer{p}
		Logger.Warn(e)
		s.sendStatus(http.StatusUnauthorized, e)
		return
	}
	m["source_fp"] = s.FP
	m["source_name"] = s.Name

	delete(m, "target")
	p.send <- m
}
func (h *Hub) run() {
	for {
		select {
		case peer := <-h.register:
			h.peers[peer.FP] = peer
		case peer := <-h.unregister:
			if _, ok := h.peers[peer.FP]; ok {
				delete(h.peers, peer.FP)
				close(peer.send)
			}
		case message := <-h.requests:
			sFP := message["source"]
			source, found := h.peers[sFP]
			if !found {
				Logger.Errorf("Hub ugnores a bad request because of wrong source: %s", sFP)
				continue
			}
			_, offer := message["offer"]
			_, answer := message["answer"]
			if offer || answer {
				h.forwardSignal(source, message)
			}
		}
	}
}

func (h *Hub) Close() {
	h.redis.Close()
}
