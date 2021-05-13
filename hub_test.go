package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSetPeerOnline(t *testing.T) {
	startTest(t)
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "1", "online", "0")
	c := &Conn{User: "j", FP: "A"}
	c.SetOnline(true)
	require.Equal(t, "1", redisDouble.HGet("peer:A", "online"))
	c.SetOnline(false)
	require.Equal(t, "0", redisDouble.HGet("peer:A", "online"))
}
func TestPeersNotifications(t *testing.T) {
	startTest(t)
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "name", "bar", "kind", "lay",
		"user", "j", "verified", "0")
	redisDouble.SAdd("user:j", "A", "B")
	wsA, err := openWS("ws://127.0.0.1:17777/ws?fp=A&name=foo&kind=lay&email=j")
	defer wsA.Close()
	wsB, err := openWS("ws://127.0.0.1:17777/ws?fp=B&name=bar&kind=lay&email=j")
	require.Nil(t, err)
	defer wsB.Close()
	if err := wsA.SetReadDeadline(time.Now().Add(time.Second / 100)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var i map[string]interface{}
	err = wsA.ReadJSON(&i)
	require.Nil(t, err)
	_, found := i["peers"]
	require.True(t, found, "No peers in: %v", i)
	if err := wsB.SetReadDeadline(time.Now().Add(time.Second / 100)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	err = wsB.ReadJSON(&i)
	require.NotNil(t, err, "Managed to read: %v", i)
}
