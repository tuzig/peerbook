package main

import (
	"fmt"
	"github.com/gomodule/redigo/redis"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestGetPeer(t *testing.T) {
	startTest(t)
	redisDouble.HSet("peer:foo", "fp", "foo", "name", "fucked up")
	exists, err := redis.Bool(db.conn.Do("EXISTS", "peer:foo"))
	require.Nil(t, err)
	require.True(t, exists)
	pd, err := db.GetPeer("foo")
	require.Nil(t, err)
	require.Equal(t, "fucked up", pd.Name)
}
func TestAddPeer(t *testing.T) {
	startTest(t)
	redisDouble.SAdd("user:j", "foo", "bar")
	peer := &Peer{DBPeer{FP: "publickey", Name: "Yosi", User: "J",
		CreatedOn: time.Now().Unix()}, nil}
	err := db.AddPeer(peer)
	require.Nil(t, err)
	exists, err := redis.Bool(db.conn.Do("EXISTS", "peer:publickey"))
	require.Nil(t, err)
	require.True(t, exists)
	pd, err := db.GetPeer("publickey")
	require.Nil(t, err)
	require.Equal(t, "publickey", pd.FP)
	require.Equal(t, "Yosi", pd.Name)
	redisDouble.Del("user:j")
}
func TestGetUserList(t *testing.T) {
	startTest(t)
	redisDouble.HSet("peer:foo", "name", "fucked up", "user", "j")
	redisDouble.HSet("peer:bar", "name", "behind a. recognition", "user", "j")
	redisDouble.SAdd("user:j", "foo", "bar")
	list, err := db.GetUserPeers("j")
	require.Nil(t, err)
	require.Equal(t, "fucked up", (*list)[1].Name)
	require.Equal(t, "behind a. recognition", (*list)[0].Name)
}
func TestVerifyPeer(t *testing.T) {
	startTest(t)
	redisDouble.HSet("peer:bar", "fp", "bar", "name", "behind a. recognition", "user", "j")
	redisDouble.SAdd("user:j", "bar")
	list, err := db.GetUserPeers("j")
	require.Nil(t, err)
	peer := (*list)[0]
	require.Equal(t, false, peer.Verified)
	peer.Verify(true)
	require.Equal(t, "1", redisDouble.HGet("peer:bar", "verified"))
}
func TestCreateToken(t *testing.T) {
	startTest(t)
	token, err := db.CreateToken("j")
	require.Nil(t, err)
	key := fmt.Sprintf("token:%s", token)
	time.Sleep(time.Millisecond)
	exists := redisDouble.Exists(key)
	require.Nil(t, err)
	require.True(t, exists)
}
