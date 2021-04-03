// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
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
}

// forwardSignal Forwards offers and answers after it ensures the peer is known
// and is verified
func (h *Hub) forwardSignal(s *Peer, m map[string]string) {
	if !s.Verified {
		e := &UnauthorizedPeer{s}
		Logger.Warn(e)
		s.sendStatus(http.StatusUnauthorized, e)
		return
	}
	target := m["target"]
	p, found := h.peers[target]
	if !found {
		e := &TargetNotFound{target}
		Logger.Warn(e)
		s.sendStatus(http.StatusBadRequest, e)
		return
	}
	if p.User != s.User {
		e := &PeerIsForeign{p}
		Logger.Warn(e)
		s.sendStatus(http.StatusBadRequest, e)
		return
	}
	m["source_fp"] = s.FP
	m["source_name"] = s.Name

	delete(m, "target")
	delete(m, "source")
	p.Send(m)
}
func (h *Hub) run() {
	for {
		select {
		case peer := <-h.register:
			h.peers[peer.FP] = peer
			db.AddPeer(peer)
		case peer := <-h.unregister:
			if _, ok := h.peers[peer.FP]; ok {
				delete(h.peers, peer.FP)
			}
		case message := <-h.requests:
			sFP := message["source"]
			source, found := h.peers[sFP]
			if !found {
				Logger.Errorf("Hub ignores a bad request because of wrong source: %s", sFP)
				continue
			}
			_, offer := message["offer"]
			_, answer := message["answer"]
			cmd, command := message["command"]
			if offer || answer {
				h.forwardSignal(source, message)
				continue
			}
			if command && (cmd == "get_list") {
				err := source.sendList()
				if err != nil {
					Logger.Errorf("Failed to send a list of peers: %w", err)
				}
			}
		}
	}
}
