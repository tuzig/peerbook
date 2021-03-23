package main

import (
	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"testing"
	"time"
)

var cstDialer = websocket.Dialer{
	Subprotocols:     []string{"p1", "p2"},
	ReadBufferSize:   1024,
	WriteBufferSize:  1024,
	HandshakeTimeout: 30 * time.Second,
}

var mainRunning bool
var redisDouble *miniredis.Miniredis

func startTest(t *testing.T) {
	if !mainRunning {
		Logger = zaptest.NewLogger(t).Sugar()
		go main()
		mainRunning = true
		s, err := miniredis.Run()
		require.Nil(t, err)
		redisDouble = s
		redisConnect(s.Addr())
		// let the server open
		time.Sleep(time.Second / 100)
	}
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
	url := "ws://127.0.0.1:17777/ws?fp=BADWOLF"
	ws, _, err := cstDialer.Dial(url, nil)
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
	redisDouble.HSet("peer:foo", "name", "bar", "kind", "lay", "user", "UUID")
	// create client, connect to the hu
	url2 := "ws://127.0.0.1:17777/ws?fp=foo&name=bar&kind=lay&user=UUID"
	ws2, _, err := cstDialer.Dial(url2, nil)
	require.Nil(t, err)
	defer ws2.Close()
	if err := ws.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	err = ws.WriteJSON(map[string]string{"offer": "an offer", "target": "foo"})
	require.Nil(t, err)
	err = ws.SetReadDeadline(time.Now().Add(time.Second))
	require.Nil(t, err)
	err = ws.ReadJSON(&s)
	require.Nil(t, err)
	require.Equal(t, 401, s.Code)
	// TODO: get ws2 to try and connect to ensure the server is not forwarding
	// requests
}
func TestSignaling(t *testing.T) {
	startTest(t)
	redisDouble.HSet("peer:A", "name", "foo", "kind", "lay", "user", "UUID1")
	redisDouble.HSet("peer:B", "name", "bar", "kind", "lay", "user", "UUID2")
	// create client, connect to the hu
	urlA := "ws://127.0.0.1:17777/ws?fp=A&name=foo&kind=lay&user=UUID1"
	wsA, _, err := cstDialer.Dial(urlA, nil)
	require.Nil(t, err)
	defer wsA.Close()
	urlB := "ws://127.0.0.1:17777/ws?fp=B&name=bar&kind=lay&user=UUID2"
	wsB, _, err := cstDialer.Dial(urlB, nil)
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
