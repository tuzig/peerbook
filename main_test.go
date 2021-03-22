package main

import (
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

func TestBadConnectionRequest(t *testing.T) {
	Logger = zaptest.NewLogger(t).Sugar()
	go main()
	// let the server open
	time.Sleep(time.Second / 100)
	// create client, connect to the hu
	url := "ws://127.0.0.1:17777/ws"
	_, resp, err := cstDialer.Dial(url, nil)
	require.NotNil(t, err)
	require.Equal(t, resp.StatusCode, 400)
	// defer ws.Close()
	/*
		const message = "Hello World!"
		if err := ws.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
		if err := ws.WriteMessage(TextMessage, []byte(message)); err != nil {
			t.Fatalf("WriteMessage: %v", err)
		}
		if err := ws.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		_, p, err := ws.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage: %v", err)
		}
		if string(p) != message {
			t.Fatalf("message=%s, want %s", p, message)
		}
	*/
}
