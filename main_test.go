package main

import (
	"encoding/json"
	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"
)

var cstDialer = websocket.Dialer{
	ReadBufferSize:   1024,
	WriteBufferSize:  1024,
	HandshakeTimeout: 30 * time.Second,
}

var mainRunning bool

func startTest(t *testing.T) {
	if !mainRunning {
		var err error
		Logger = zaptest.NewLogger(t).Sugar()
		redisDouble, err = miniredis.Run()
		require.Nil(t, err)
		go main()
		mainRunning = true
		// let the server open
	} else {
		hub.peers = map[string]*Peer{}
		redisDouble.FlushAll()
	}
	time.Sleep(time.Millisecond)
}
func openWS(url string) (*websocket.Conn, error) {
	time.Sleep(time.Millisecond)
	ws, _, err := cstDialer.Dial(url, nil)
	return ws, err
}
func TestBadConnectionRequest(t *testing.T) {
	startTest(t)
	// create client, connect to the hu
	url := "ws://127.0.0.1:17777/ws"
	_, resp, err := cstDialer.Dial(url, nil)
	require.NotNil(t, err)
	require.Equal(t, resp.StatusCode, 400)
}
func TestUnknownFingerprint(t *testing.T) {
	startTest(t)
	// create client, connect to the hu
	ws, err := openWS("ws://127.0.0.1:17777/ws?fp=BADWOLF&email=cracker@forbidden.com")
	require.Nil(t, err)
	defer ws.Close()
	if err := ws.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var s StatusMessage
	err = ws.ReadJSON(&s)
	require.Nil(t, err)
	require.Equal(t, 401, s.Code)
	// try and communicate with another peer
	redisDouble.HSet("peer:foo", "fp", "foo", "name", "bar", "kind", "lay", "user", "UUID")
	// create client, connect to the hu
	ws2, err := openWS("ws://127.0.0.1:17777/ws?fp=foo&name=bar&kind=lay&email=UUID")

	require.Nil(t, err)
	defer ws2.Close()
	if err := ws.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	err = ws.WriteJSON(map[string]string{"offer": "an offer", "target": "foo"})
	require.Nil(t, err)
	time.Sleep(time.Second / 10)
	err = ws.SetReadDeadline(time.Now().Add(time.Second))
	require.Nil(t, err)
	err = ws.ReadJSON(&s)
	require.Nil(t, err)
	require.Equal(t, 401, s.Code)
}
func TestSignalingAcrossUsers(t *testing.T) {
	startTest(t)
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "name", "bar", "kind", "lay",
		"user", "h", "verified", "1")
	// create client, connect to the hu
	wsA, err := openWS("ws://127.0.0.1:17777/ws?fp=A&name=foo&kind=lay&email=j")
	require.Nil(t, err)
	defer wsA.Close()
	wsB, err := openWS("ws://127.0.0.1:17777/ws?fp=B&name=bar&kind=lay&email=h")
	require.Nil(t, err)
	defer wsB.Close()
	err = wsA.SetWriteDeadline(time.Now().Add(time.Second))
	require.Nil(t, err)
	err = wsA.WriteJSON(map[string]string{"offer": "an offer", "target": "B"})
	require.Nil(t, err)
	if err := wsB.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var o OfferMessage
	err = wsB.ReadJSON(&o)
	require.NotNil(t, err)
	if err := wsA.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var s StatusMessage
	err = wsA.ReadJSON(&s)
	require.Nil(t, err)
	require.Equal(t, 400, s.Code)
}
func TestValidSignaling(t *testing.T) {
	startTest(t)
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "name", "bar", "kind", "lay",
		"user", "j", "verified", "1")
	// create client, connect to the hu
	wsA, err := openWS("ws://127.0.0.1:17777/ws?fp=A&name=foo&kind=lay&email=j")
	defer wsA.Close()
	wsB, err := openWS("ws://127.0.0.1:17777/ws?fp=B&name=bar&kind=lay&email=j")
	require.Nil(t, err)
	defer wsB.Close()
	hub.peers["A"].Verified = true
	hub.peers["B"].Verified = true
	err = wsA.SetWriteDeadline(time.Now().Add(time.Second))
	require.Nil(t, err)
	err = wsA.WriteJSON(map[string]string{"offer": "an offer", "target": "B"})
	require.Nil(t, err)
	if err := wsB.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var o OfferMessage
	err = wsB.ReadJSON(&o)
	require.Nil(t, err)
	require.Equal(t, "an offer", o.Offer)
	require.Equal(t, "foo", o.SourceName)
	err = wsB.SetWriteDeadline(time.Now().Add(time.Second))
	require.Nil(t, err)
	err = wsB.WriteJSON(map[string]string{"answer": "B's answer", "target": "A"})
	require.Nil(t, err)
	if err := wsA.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var a AnswerMessage
	err = wsA.ReadJSON(&a)
	require.Equal(t, "B's answer", a.Answer)
	require.Equal(t, "bar", a.SourceName)
}
func TestNewPeerConnect(t *testing.T) {
	startTest(t)
	s := time.Now()
	ws, err := openWS("ws://127.0.0.1:17777/ws?fp=foo&name=fuckedup")
	require.Nil(t, err)
	defer ws.Close()
	time.Sleep(time.Second / 100)
	n := redisDouble.HGet("peer:foo", "name")
	require.Equal(t, "fuckedup", n)
	c := redisDouble.HGet("peer:foo", "created_on")
	ci, err := strconv.Atoi(c)
	require.Nil(t, err)
	require.InDelta(t, s.Unix(), int64(ci), 1)
}
func TestGetUsersList(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token and two peers
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.Set("token:avalidtoken", "j")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0")
	redisDouble.HSet("peer:B", "fp", "B", "name", "bar", "kind", "lay",
		"user", "j", "verified", "1")
	resp, err := http.Get("http://127.0.0.1:17777/list/avalidtoken")
	require.Nil(t, err)
	defer resp.Body.Close()
	list := make([]map[string]interface{}, 2)
	err = json.NewDecoder(resp.Body).Decode(&list)
	require.Nil(t, err)
	require.Equal(t, 2, len(list))
	require.Equal(t, map[string]interface{}{
		"kind": "lay", "name": "foo", "user": "j", "fp": "A"},
		list[0])
	require.Equal(t, map[string]interface{}{
		"kind": "lay", "name": "bar", "user": "j", "verified": true, "fp": "B"},
		list[1])
}
func TestHTTPPeerVerification(t *testing.T) {
	var s StatusMessage

	startTest(t)
	// setup the fixture - a user, his token and two peers
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.Set("token:avalidtoken", "j")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "1")
	ws, err := openWS("ws://127.0.0.1:17777/ws?fp=B&name=bar")
	require.Nil(t, err)
	defer ws.Close()
	err = ws.ReadJSON(&s)
	require.Nil(t, err)
	require.Equal(t, 401, s.Code)
	time.Sleep(time.Second / 100)
	resp, err := http.PostForm("http://127.0.0.1:17777/list/avalidtoken",
		url.Values{"B": {"checked"}})
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)
	time.Sleep(time.Second / 100)
	require.Equal(t, "0", redisDouble.HGet("peer:A", "verified"))
	require.Equal(t, "1", redisDouble.HGet("peer:B", "verified"))
	err = ws.ReadJSON(&s)
	require.Nil(t, err)
	require.Equal(t, 200, s.Code)
}
