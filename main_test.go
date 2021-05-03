package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"net/http"
	"net/url"
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
		hub.conns = map[string]*Conn{}
		redisDouble.FlushAll()
	}
	time.Sleep(time.Millisecond * 10)
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
	_, err := openWS("ws://127.0.0.1:17777/ws?fp=BADWOLF&email=cracker@forbidden.com")
	require.NotNil(t, err)
}
func TestSignalingAcrossUsers(t *testing.T) {
	startTest(t)
	redisDouble.SetAdd("user:j", "A")
	redisDouble.SetAdd("user:h", "B")
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
	// clean the pipe by reading the first three peers messages
	var pl map[string]*PeerList
	if err = wsA.SetReadDeadline(time.Now().Add(time.Second / 100)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	err = wsA.ReadJSON(&pl)
	require.Nil(t, err)
	require.Contains(t, pl, "peers")
	if err = wsB.SetReadDeadline(time.Now().Add(time.Second / 100)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	err = wsB.ReadJSON(&pl)
	require.Nil(t, err)
	require.Contains(t, pl, "peers")
	err = wsA.SetWriteDeadline(time.Now().Add(time.Second))
	require.Nil(t, err)
	err = wsA.WriteJSON(map[string]string{"offer": "an offer", "target": "B"})
	require.Nil(t, err)
	if err := wsB.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var o OfferMessage
	err = wsB.ReadJSON(&o)
	require.NotNil(t, err, "Got message %v", o)
	if err := wsA.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var s StatusMessage
	err = wsA.ReadJSON(&s)
	require.Nil(t, err)
	require.Equal(t, 401, s.Code)
}
func TestValidSignaling(t *testing.T) {
	startTest(t)
	redisDouble.SetAdd("user:j", "A", "B")
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
	hub.conns["A"].Verified = true
	hub.conns["B"].Verified = true
	// read all the peers messages
	var pl map[string]*PeerList
	if err = wsA.SetReadDeadline(time.Now().Add(time.Second / 100)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	err = wsA.ReadJSON(&pl)
	require.Nil(t, err)
	require.Contains(t, pl, "peers")
	if err = wsA.SetReadDeadline(time.Now().Add(time.Second / 100)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	err = wsA.ReadJSON(&pl)
	require.Nil(t, err)
	require.Contains(t, pl, "peers")
	if err = wsB.SetReadDeadline(time.Now().Add(time.Second / 100)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	err = wsB.ReadJSON(&pl)
	require.Nil(t, err)
	require.Contains(t, pl, "peers")
	// end of peers messages
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
}
func TestGetUsersList(t *testing.T) {
	startTest(t)
	token := "=a+valid/token="
	// setup the fixture - a user, his token and two peers
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.Set(fmt.Sprintf("token:%s", token), "j")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0")
	redisDouble.HSet("peer:B", "fp", "B", "name", "bar", "kind", "lay",
		"user", "j", "verified", "1")
	ws, err := openWS("ws://127.0.0.1:17777/ws?fp=B&name=bar&email=j&kind=lay")
	require.Nil(t, err)
	defer ws.Close()
	listU := fmt.Sprintf("http://127.0.0.1:17777/list/%s", url.PathEscape(token))
	resp, err := http.Get(listU)
	require.Nil(t, err)
	defer resp.Body.Close()
	list := make([]map[string]interface{}, 2)
	err = json.NewDecoder(resp.Body).Decode(&list)
	require.Nil(t, err)
	require.Equal(t, 2, len(list))
	require.Equal(t, map[string]interface{}{
		"kind": "lay", "name": "foo", "user": "j", "fp": "A", "online": false},
		list[0])
	require.Equal(t, map[string]interface{}{
		"kind": "lay", "name": "bar", "user": "j", "verified": true, "fp": "B",
		"online": true},
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
	redisDouble.HSet("peer:B", "fp", "B", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0")
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
func TestVerifyUnverified(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token and two peers
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0")
	redisDouble.HSet("peer:B", "fp", "B", "name", "bar", "kind", "lay",
		"user", "j", "verified", "1")
	msg := map[string]string{"fp": "A", "email": "j"}
	m, err := json.Marshal(msg)
	require.Nil(t, err)
	resp, err := http.Post("http://127.0.0.1:17777/verify", "application/json",
		bytes.NewBuffer(m))
	require.Nil(t, err)
	defer resp.Body.Close()
	var ret map[string]bool
	err = json.NewDecoder(resp.Body).Decode(&ret)
	require.Nil(t, err)
	require.False(t, ret["verified"])
}
func TestVerifyNew(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token and two peers
	msg := map[string]string{"fp": "A", "email": "j", "kind": "server",
		"name": "foo"}
	m, err := json.Marshal(msg)
	require.Nil(t, err)
	resp, err := http.Post("http://127.0.0.1:17777/verify", "application/json",
		bytes.NewBuffer(m))
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
	var ret map[string]bool
	err = json.NewDecoder(resp.Body).Decode(&ret)
	require.Nil(t, err)
	require.False(t, ret["verified"])
	require.Equal(t, "0", redisDouble.HGet("peer:A", "verified"))
	require.Equal(t, "foo", redisDouble.HGet("peer:A", "name"))
	require.Equal(t, "server", redisDouble.HGet("peer:A", "kind"))
}
func TestVerifyVerified(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token and two peers
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0")
	redisDouble.HSet("peer:B", "fp", "B", "name", "bar", "kind", "lay",
		"user", "j", "verified", "1")
	msg := map[string]string{"fp": "B", "email": "j"}
	m, err := json.Marshal(msg)
	require.Nil(t, err)
	resp, err := http.Post("http://127.0.0.1:17777/verify", "application/json",
		bytes.NewBuffer(m))
	require.Nil(t, err)
	defer resp.Body.Close()
	var ret map[string]bool
	err = json.NewDecoder(resp.Body).Decode(&ret)
	require.Nil(t, err)
	require.True(t, ret["verified"])
}
func TestVerifyWrongUser(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token and two peers
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0")
	redisDouble.HSet("peer:B", "fp", "B", "name", "bar", "kind", "lay",
		"user", "j", "verified", "1")

	msg := map[string]string{"fp": "B", "email": "i"}
	m, err := json.Marshal(msg)
	require.Nil(t, err)
	resp, err := http.Post("http://127.0.0.1:17777/verify", "application/json",
		bytes.NewBuffer(m))
	require.Nil(t, err, err)
	require.Equal(t, 409, resp.StatusCode)
}
func TestValidatePeerNPublish(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token and two peers
	redisDouble.Set("token:avalidtoken", "j")
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0")
	redisDouble.HSet("peer:B", "fp", "B", "name", "bar", "kind", "lay",
		"user", "j", "verified", "1")

	wsA, err := openWS("ws://127.0.0.1:17777/ws?fp=A&name=foo&kind=lay&email=j")
	require.Nil(t, err)
	defer wsA.Close()
	wsB, err := openWS("ws://127.0.0.1:17777/ws?fp=B&name=bar&kind=lay&email=j")
	require.Nil(t, err)
	defer wsB.Close()
	var s StatusMessage
	if err = wsA.SetReadDeadline(time.Now().Add(time.Second / 100)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	err = wsA.ReadJSON(&s)
	require.Nil(t, err)
	require.Equal(t, 401, s.Code)
	if err = wsB.SetReadDeadline(time.Now().Add(time.Second / 100)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var pl map[string]*PeerList
	err = wsB.ReadJSON(&pl)
	require.Nil(t, err)
	require.Contains(t, pl, "peers")
	resp, err := http.PostForm("http://127.0.0.1:17777/list/avalidtoken",
		url.Values{"A": {"checked"}, "B": {"checked"}})
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
	require.Equal(t, "1", redisDouble.HGet("peer:A", "verified"))
	// read the upodated status
	if err = wsA.SetReadDeadline(time.Now().Add(time.Second / 100)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	err = wsA.ReadJSON(&s)
	require.Nil(t, err)
	require.Equal(t, 200, s.Code)
	// and the peers
	if err = wsA.SetReadDeadline(time.Now().Add(time.Second / 100)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	err = wsA.ReadJSON(&pl)
	require.Nil(t, err)
	require.Contains(t, pl, "peers")
	if err = wsB.SetReadDeadline(time.Now().Add(time.Second / 100)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	err = wsB.ReadJSON(&pl)
	require.Nil(t, err)
	require.Contains(t, pl, "peers")
	time.Sleep(time.Millisecond)
}
func TestHTTPrmrf(t *testing.T) {

	startTest(t)
	// setup the fixture - a user, his token and two peers
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.Set("token:avalidtoken", "j")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0")
	resp, err := http.PostForm("http://127.0.0.1:17777/list/avalidtoken",
		url.Values{"rmrf": {"checked"}})
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)
	time.Sleep(time.Second / 100)
	require.False(t, redisDouble.Exists("peer:A"))
	require.False(t, redisDouble.Exists("peer:B"))
	require.False(t, redisDouble.Exists("user:j"))
}
