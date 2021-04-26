// based on Gorilla WebSocket.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"gopkg.in/gomail.v2" //go get gopkg.in/gomail.v2
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 6 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = 5 * time.Second

	// Maximum message size allowed from peer.
	maxMessageSize = 4096
	DefaultHomeUrl = "https://pb.terminal7.dev"
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

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
	Verified    bool   `redis:"verified" json:"verified,omitempty"`
	CreatedOn   int64  `redis:"created_on" json:"created_on,omitempty"`
	VerifiedOn  int64  `redis:"verified_on" json:"verified_on,omitempty"`
	LastConnect int64  `redis:"last_connect" json:"last_connect,omitempty"`
	// is it online?
	Online bool `redis:"-" json:"online"`
	// The websocket connection.
	ws *websocket.Conn
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

// PeerFromQ retruns a fresh Peer based on query paramets: fp, name, kind &
// email
func PeerFromQ(q url.Values) (*Peer, error) {
	fp := q.Get("fp")
	if fp == "" {
		return nil, fmt.Errorf("Missing `fp` query parameter")
	}
	return &Peer{FP: fp, Name: q.Get("name"), Kind: q.Get("kind"),
		CreatedOn: time.Now().Unix(), User: q.Get("email"), Verified: false,
		Online: true}, nil
}

// LoadPeer loads a peer from redis based on a given peer
func LoadPeer(baseP *Peer) (*Peer, error) {
	peer, found := hub.peers[baseP.FP]
	if found {
		return peer, nil
	}
	exists, err := db.PeerExists(baseP.FP)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, &PeerNotFound{}
	}
	var p Peer
	key := fmt.Sprintf("peer:%s", baseP.FP)
	db.getDoc(key, &p)
	// ensure the same details
	if p.User != baseP.User || p.Kind != baseP.Kind {
		return nil, &PeerChanged{}
	}
	return &p, nil
}

// readPump pumps messages from the websocket connection to the hub.
//
// The application runs readPump in a per-connection goroutine. The application
// ensures that there is at most one reader on a connection by executing all
// reads from this goroutine.
func (p *Peer) readPump() {

	defer func() {
		hub.unregister <- p
		if p.ws != nil {
			p.ws.Close()
			p.ws = nil
		}
	}()
	p.ws.SetReadLimit(maxMessageSize)
	p.ws.SetPongHandler(func(string) error {
		p.ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	for {
		var message map[string]interface{}
		p.ws.SetReadDeadline(time.Now().Add(pongWait))
		err := p.ws.ReadJSON(&message)
		if err != nil {
			Logger.Errorf("read pump got an error: %w", err)
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				Logger.Errorf("ws error: %w", err)
			}
			break
		}
		// TODO: do we use the "source" ?
		if !p.Verified {
			e := &UnauthorizedPeer{p}
			Logger.Warn(e)
			p.sendStatus(http.StatusUnauthorized, e)
			continue
		}
		message["source"] = p.FP
		hub.requests <- message
	}
}

// pinger sends pings
func (p *Peer) pinger() {
	errRun := 0
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		if p.ws != nil {
			p.ws.Close()
			p.ws = nil
		}
	}()
	for {
		select {
		case <-ticker.C:
			if p.ws == nil {
				break
			}
			p.ws.SetWriteDeadline(time.Now().Add(writeWait))
			err := p.ws.WriteMessage(websocket.PingMessage, nil)
			if err != nil {
				Logger.Errorf("failed to send ping message: %s", err)
				errRun++
				if errRun == 3 {
					return
				}
			} else {
				errRun = 0
			}
		}
	}
}
func (p *Peer) sendStatus(code int, e error) error {
	msg := StatusMessage{code, e.Error()}
	return p.Send(msg)
}

// Send send a message as json
func (p *Peer) Send(msg interface{}) error {
	if p.ws == nil {
		return fmt.Errorf("trying to send a message to closed websocket: %v", msg)
	}
	return p.ws.WriteJSON(msg)
}

// sendAuthEmail creates a short lived token and emails a message with a link
// to `/auth/<token>` so the javascript at /auth can read the list of peers and
// use checkboxes to enable/disable

func sendAuthEmail(email string) {
	// TODO: send an email in the background
	token, err := db.CreateToken(email)
	if err != nil {
		Logger.Errorf("Failed to create token: %w", err)
		return
	}
	m := gomail.NewMessage()
	homeUrl := os.Getenv("PB_HOME_URL")
	if homeUrl == "" {
		homeUrl = DefaultHomeUrl
	}
	clickL := fmt.Sprintf("%s/auth/%s", homeUrl, token)
	m.SetBody("text/html", `<html lang=en> <head><meta charset=utf-8>
<title>Peerbook updates for your approval</title>
</head>
Please click <a href="`+clickL+`">here to review</a>.`)

	text := fmt.Sprintf("Please click to review:\n%s", clickL)
	m.AddAlternative("text/plain", text)

	m.SetHeaders(map[string][]string{
		"From":               {m.FormatAddress("support@terminal7.dev", "Terminal7")},
		"To":                 {email},
		"Subject":            {"Pending changes to your peerbook"},
		"X-SES-MESSAGE-TAGS": {"genre=auth_email"},
		// Comment or remove the next line if you are not using a configuration set
		// "X-SES-CONFIGURATION-SET": {ConfigSet},
	})

	host := os.Getenv("PB_SMTP_HOST")
	user := os.Getenv("PB_SMTP_USER")
	pass := os.Getenv("PB_SMTP_PASS")
	d := gomail.NewPlainDialer(host, 587, user, pass)

	Logger.Infof("Sending email %q", text)
	// Display an error message if something goes wrong; otherwise,
	// display a message confirming that the message was sent.
	if err := d.DialAndSend(m); err != nil {
		Logger.Errorf("Failed to send email: %s", err)
	} else {
		Logger.Infof("Send email to %q", email)
	}
}

// Upgrade upgrade an http request to a websocket and stores it
func (p *Peer) Upgrade(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		Logger.Errorf("Failed to upgrade socket: %w", err)
	}
	p.ws = conn
}

func (p *Peer) sendList() error {
	l, err := GetUsersPeers(p.User)
	if err != nil {
		return err
	}
	return p.Send(map[string]*PeerList{"peers": l})
}

// serveWs handles websocket requests from the peer.
func serveWs(w http.ResponseWriter, r *http.Request) {
	var notFound bool
	q := r.URL.Query()
	Logger.Infof("Got a new peer request: %v", q)
	qp, err := PeerFromQ(q)
	if err != nil {
		msg := fmt.Sprintf("Bad peer requested: %s", err)
		Logger.Warn(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	peer, err := LoadPeer(qp)
	if err != nil {
		_, notFound = err.(*PeerNotFound)
		_, changed := err.(*PeerChanged)
		if changed {
			msg := fmt.Sprintf("Request from a weird peer: %s", err)
			Logger.Warn(msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		if notFound {
			Logger.Infof("Peer not found, using peer from Q %v", qp)
			// rollback - work with the unverified peer from the query
			peer = qp
		} else {
			Logger.Warnf("Refusing a bad request: %s", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	peer.Upgrade(w, r)
	hub.register <- peer
	go peer.pinger()
	go peer.readPump()
	// if it's an unverified peer, keep the connection open and send a status message
	if !peer.Verified {
		peer.sendStatus(401, fmt.Errorf(
			"Unverified peer, please check your inbox to verify"))
	}
}

// Getting the list of users peers
func GetUsersPeers(email string) (*PeerList, error) {
	var l PeerList
	u, err := db.GetUser(email)
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

// GetPeer gets a peer, using the hub as cache for connected peers
func GetPeer(fp string) (*Peer, error) {
	peer, found := hub.peers[fp]
	if found {
		return peer, nil
	}
	key := fmt.Sprintf("peer:%s", fp)
	var pd Peer
	err := db.getDoc(key, &pd)
	if err != nil {
		return nil, err
	}
	return &pd, nil
}
func (p *Peer) Key() string {
	return fmt.Sprintf("peer:%s", p.FP)
}

// Verify grants or revokes authorization from a peer
func (p *Peer) setName(name string) {
	p.Name = name
	conn := db.pool.Get()
	defer conn.Close()
	conn.Do("HSET", p.Key(), "name", name)
}
func (p *Peer) Verify(v bool) {
	conn := db.pool.Get()
	defer conn.Close()
	if v {
		conn.Do("HSET", p.Key(), "verified", "1")
		p.Send(StatusMessage{200, "peer is verified"})
		Logger.Infof("Sent a 200 to a newly verified peer")
	} else {
		conn.Do("HSET", p.Key(), "verified", "0")
		p.sendStatus(401, fmt.Errorf("peer's verification was revoked"))
	}
	p.Verified = v
	if p2, inmem := hub.peers[p.FP]; inmem {
		p2.Verified = v
	}
}
