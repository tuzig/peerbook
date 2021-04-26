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
	requests chan map[string]interface{}

	// Register requests from the peers.
	register chan *Peer

	// Unregister requests from peers.
	unregister chan *Peer
}

// forwardSignal Forwards offers and answers after it ensures the peer is known
// and is verified
func (h *Hub) forwardSignal(s *Peer, m map[string]interface{}) {
	target := m["target"].(string)
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
	Logger.Infof("Forwarding: %v", m)
	m["source_fp"] = s.FP
	m["source_name"] = s.Name

	delete(m, "target")
	p.Send(m)
}

// notifyPeers is called when the peer list changes
func (h *Hub) notifyPeers(u string) error {
	peers, err := GetUsersPeers(u)
	if err != nil {
		return err
	}
	return h.multicast(peers, map[string]interface{}{"peers": peers})
}
func (h *Hub) multicast(peers *PeerList, msg map[string]interface{}) error {
	for _, p := range *peers {
		if p.Online && p.Verified {
			Logger.Infof("Sending message to peer %q", p.Name)
			err := p.Send(msg)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
func (h *Hub) run() {
	for {
		select {
		case peer := <-h.register:
			peer.Online = true
			h.peers[peer.FP] = peer
			db.AddPeer(peer)
			err := h.notifyPeers(peer.User)
			if err != nil {
				Logger.Warnf("Failed to notify peers of list change: %s", err)
			}
		case peer := <-h.unregister:
			Logger.Infof("Unregistering peer %s", peer.Name)
			if _, ok := h.peers[peer.FP]; ok {
				delete(h.peers, peer.FP)
				err := h.notifyPeers(peer.User)
				if err != nil {
					Logger.Warnf("Failed to notify peers of list change: %s", err)
				}
			}
		case message := <-h.requests:
			sFP := message["source"]
			delete(message, "source")
			source, found := h.peers[sFP.(string)]
			if !found {
				Logger.Errorf("Hub ignores a bad request because of wrong source: %s", sFP)
				continue
			}
			_, offer := message["offer"]
			_, answer := message["answer"]
			_, candidate := message["candidate"]
			if offer || answer || candidate {
				h.forwardSignal(source, message)
				continue
			}
			cmd, command := message["command"]
			if command && (cmd == "get_list") {
				err := source.sendList()
				if err != nil {
					Logger.Errorf("Failed to send a list of peers: %w", err)
				}
			}
		}
	}
}
