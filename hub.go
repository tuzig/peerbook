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
			c.SendPeerList()
			if err := c.SetOnline(true); err != nil {
				Logger.Errorf("Failed setting a peer as online: %s", err)
				continue
			}
		case c := <-h.unregister:
			if c.WS != nil {
				c.WS.Close()
			}
			if err := c.SetOnline(false); err != nil {
				Logger.Errorf("Failed setting a peer as offline: %s", err)
				continue
			}
		}
	}
}
