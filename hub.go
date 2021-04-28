// Copyright 2021 TUZIG LTD and peerbook Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/gomodule/redigo/redis"
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
	peers, err := GetUsersPeers(u)
	if err != nil {
		return err
	}
	return h.multicast(peers, map[string]interface{}{"peers": peers})
}
func (h *Hub) multicast(peers *PeerList, msg map[string]interface{}) error {
	for _, p := range *peers {
		if p.Online && p.Verified {
			c, found := h.conns[p.FP]
			if found {
				Logger.Infof("Sending message to peer %q", p.Name)
				err := c.Send(msg)
				if err != nil {
					return err
				}
			} else {
				Logger.Warnf("Peer Online mismatch")
			}
		}
	}
	return nil
}

func (h *Hub) SetPeerOnline(fp string, o bool) error {
	key := fmt.Sprintf("peer:%s", fp)
	rc := db.pool.Get()
	defer rc.Close()
	if _, err := rc.Do("HSET", key, "online", o); err != nil {
		return err
	}
	email, err := redis.String(rc.Do("HGET", key, "user"))
	if err != nil {
		return fmt.Errorf("Failed reading fp's user: %w", err)
	}
	err = h.notifyPeers(email)
	if err != nil {
		Logger.Warnf("Failed to notify peers of list change: %w", err)
	}
	return nil
}
func (h *Hub) run() {
	for {
		select {
		case c := <-h.register:
			h.conns[c.FP] = c
			if err := h.SetPeerOnline(c.FP, true); err != nil {
				Logger.Errorf("Failed setting a peer as online: %s", err)
				continue
			}
		case c := <-h.unregister:
			if c.WS != nil {
				c.WS.Close()
			}
			if err := h.SetPeerOnline(c.FP, false); err != nil {
				Logger.Errorf("Failed setting a peer as offline: %s", err)
				continue
			}
			delete(h.conns, c.FP)
		case m := <-h.requests:
			_, offer := m["offer"]
			_, answer := m["answer"]
			_, candidate := m["candidate"]
			if offer || answer || candidate {
				v, found := m["target"]
				if !found {
					Logger.Warnf("Ignoring an forwarding msg with no target")
					continue
				}
				target := v.(string)
				t, found := h.conns[target]
				if !found {
					e := &TargetNotFound{target}
					Logger.Warn(e)
					t.sendStatus(http.StatusBadRequest, e)
					continue
				}
				user, found := m["user"]
				if !found || t.User != user {
					// Notify the source Unauthorized
					Logger.Warnf("Ignoring forwarding across users")
					source, found := m["source_fp"]
					if found {
						sc, found := h.conns[source.(string)]
						if found {
							sc.sendStatus(http.StatusUnauthorized,
								fmt.Errorf("Target belongs to another user"))
						}
					}
					continue
				}
				delete(m, "user")
				delete(m, "target")
				Logger.Infof("Forwarding: %v", m)
				t.Send(m)
				continue
			}
		}
	}
}
