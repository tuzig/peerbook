// Copyright 2021 TUZIG LTD and peerbook Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
)

// Hub maintains the set of active peers and broadcasts messages to the
// peers.
type Hub struct {
	// Registered peers.

	conns map[string]*Conn

	// Inbound messages from the peers.
	requests chan map[string]interface{}

	// Register requests from the peers.
	register chan *Conn

	// Unregister requests from peers.
	unregister chan *Conn
}

// notifyPeers is called when the peer list changes
func (h *Hub) notifyPeers(u string) error {
	var peers PeerList

	ps, err := GetUsersPeers(u)
	if err != nil {
		return err
	}
	for _, p := range *ps {
		if p.Verified {
			peers = append(peers, p)
		}
	}

	return h.multicast(&peers, map[string]interface{}{"peers": peers})
}
func (h *Hub) multicast(peers *PeerList, msg map[string]interface{}) error {
	u := ""
	for _, p := range *peers {
		if p.Online && p.Verified {
			c, found := h.conns[p.FP]
			if found {
				Logger.Infof("Sending message to peer %q", p.Name)
				select {
				case c.send <- msg:
				default:
					h.unregister <- c
				}
			} else {
				Logger.Warnf("Reseting peer %q to offline", p.Name)
				u = p.User
				p.SetOnline(false)
			}
		}
	}
	if u != "" {
		err := h.notifyPeers(u)
		if err != nil {
			Logger.Warnf("Failed to notify peers of list change: %w", err)
		}
	}
	return nil
}

func (h *Hub) run() {
	for {
		u := ""
		select {
		case c := <-h.register:
			h.conns[c.FP] = c
			if err := c.SetOnline(true); err != nil {
				Logger.Errorf("Failed setting a peer as online: %s", err)
				continue
			}
			u = c.User
		case c := <-h.unregister:
			if c.WS != nil {
				c.WS.Close()
			}
			if err := c.SetOnline(false); err != nil {
				Logger.Errorf("Failed setting a peer as offline: %s", err)
				continue
			}
			delete(h.conns, c.FP)
			u = c.User
		case m := <-h.requests:
			h.handleMsg(m)
		}
		if u != "" {
			err := h.notifyPeers(u)
			if err != nil {
				Logger.Warnf("Failed to notify peers of list change: %w", err)
			}
		}
	}
}
func (h *Hub) handleMsg(m map[string]interface{}) {
	_, offer := m["offer"]
	_, answer := m["answer"]
	_, candidate := m["candidate"]
	if offer || answer || candidate {
		v, found := m["target"]
		if !found {
			Logger.Warnf("Ignoring an forwarding msg with no target")
			return
		}
		tfp := v.(string)
		// TODO: verify message is not across users
		Logger.Infof("Forwarding: %v", m)
		delete(m, "user")
		delete(m, "target")
		err := SendMessage(tfp, m)
		if err != nil {
			Logger.Errorf("Failed to encode a clients msg: %s", err)
		}
	}
}
