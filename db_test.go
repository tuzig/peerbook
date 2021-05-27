package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/stretchr/testify/require"
)

func TestGetPeer(t *testing.T) {
	startTest(t)
	redisDouble.HSet("peer:foo", "fp", "foo", "name", "fucked up")
	conn := db.pool.Get()
	defer conn.Close()
	exists, err := redis.Bool(conn.Do("EXISTS", "peer:foo"))
	require.Nil(t, err)
	require.True(t, exists)
	pd, err := GetPeer("foo")
	require.Nil(t, err)
	require.Equal(t, "fucked up", pd.Name)
}
func TestAddPeer(t *testing.T) {
	startTest(t)
	redisDouble.SAdd("user:j", "foo", "bar")
	peer := &Peer{FP: "publickey", Name: "Yosi", User: "J",
		CreatedOn: time.Now().Unix()}
	err := db.AddPeer(peer)
	require.Nil(t, err)
	conn := db.pool.Get()
	defer conn.Close()
	exists, err := redis.Bool(conn.Do("EXISTS", "peer:publickey"))
	require.Nil(t, err)
	require.True(t, exists)
	pd, err := GetPeer("publickey")
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
	list, err := GetUsersPeers("j")
	require.Nil(t, err)
	require.Equal(t, "fucked up", (*list)[1].Name)
	require.Equal(t, "behind a. recognition", (*list)[0].Name)
}
func TestVerifyPeer(t *testing.T) {
	startTest(t)
	redisDouble.HSet("peer:bar", "fp", "bar", "name", "behind a. recognition",
		"user", "j", "online", "0")
	redisDouble.SAdd("user:j", "bar")
	list, err := GetUsersPeers("j")
	require.Nil(t, err)
	peer := (*list)[0]
	require.Equal(t, false, peer.Verified)
	err = VerifyPeer("bar", true)
	require.Nil(t, err)
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
func TestCanSendEmail(t *testing.T) {
	startTest(t)
	can := db.canSendEmail("j")
	require.True(t, can)
	can2 := db.canSendEmail("j")
	require.False(t, can2)
}
