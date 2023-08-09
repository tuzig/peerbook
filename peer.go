// Copyright 2021 TUZIG LTD and peerbook Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

const AuthTokenLen = 30 // in Bytes, four times that in base64 and urls

var upgrader = websocket.Upgrader{
	ReadBufferSize:  maxMessageSize,
	WriteBufferSize: maxMessageSize,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// Peer is a middleman between the websocket connection and the hub.
type Peer struct {
	FP          string `redis:"fp" json:"fp"`
	Name        string `redis:"name" json:"name,omitempty"`
	User        string `redis:"user" json:"user,omitempty"`
	Kind        string `redis:"kind" json:"kind,omitempty"`
	Verified    bool   `redis:"verified" json:"verified"`
	CreatedOn   int64  `redis:"created_on" json:"created_on,omitempty"`
	VerifiedOn  int64  `redis:"verified_on" json:"verified_on,omitempty"`
	LastConnect int64  `redis:"last_connect" json:"last_connect,omitempty"`
	Online      bool   `redis:"online" json:"online"`
	AuthToken   string `redis:"auth_token,omitempty" json:"auth_token,omitempty"`
}
type PeerList []*Peer

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

func NewPeer(fp string, name string, user string, kind string) *Peer {
	return &Peer{FP: fp, Name: name, Kind: kind, CreatedOn: time.Now().Unix(),
		User: user, Verified: false, Online: true,
		AuthToken: RandomString(AuthTokenLen),
	}
}

// Getting the list of users peers
func GetUsersPeers(uid string) (*PeerList, error) {
	var l PeerList
	u, err := db.GetPeers(uid)
	if err != nil {
		return nil, err
	}
	// TODO: use redis transaction to read them all at once
	for _, fp := range *u {
		p, err := GetPeer(fp)
		if err != nil {
			Logger.Warnf("Failed to read peer: %w", err)
		} else {
			l = append(l, p)
		}
	}
	return &l, nil
}

func (p *Peer) SetUser(uID string) {
	p.User = uID
	conn := db.pool.Get()
	defer conn.Close()
	conn.Do("HSET", p.Key(), "user", uID)
}

func (p *Peer) setName(name string) {
	p.Name = name
	conn := db.pool.Get()
	defer conn.Close()
	conn.Do("HSET", p.Key(), "name", name)
}

func (p *Peer) Key() string {
	return fmt.Sprintf("peer:%s", p.FP)
}
func (p *Peer) SinceBoot() string {
	return time.Now().Sub(time.Unix(p.CreatedOn, 0)).Truncate(time.Second).String()
}
func (p *Peer) SinceConnect() string {
	if p.LastConnect == 0 {
		return "-"
	}
	return time.Now().Sub(time.Unix(p.LastConnect, 0)).Truncate(time.Second).String()
}
