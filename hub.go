// Copyright 2021 TUZIG LTD and peerbook Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

// Hub maintains the set of active peers and broadcasts messages to the
// peers.
type Hub struct {
	// Inbound messages from the peers.
	requests chan map[string]interface{}

	// Register requests from the peers.
	register chan *Conn

	// Unregister requests from peers.
	unregister chan *Conn
}

func (h *Hub) run() {
	for {
		select {
		case c := <-h.register:
			if err := c.SetOnline(true); err != nil {
				Logger.Errorf("Failed setting a peer as online: %s", err)
				continue
			}
			c.SendPeerList()
		case c := <-h.unregister:
			if c.WS != nil {
				c.WS.Close()
			}
			if err := c.SetOnline(false); err != nil {
				Logger.Errorf("Failed setting a peer as offline: %s", err)
				continue
			}

		case m := <-h.requests:
			h.handleMsg(m)
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
