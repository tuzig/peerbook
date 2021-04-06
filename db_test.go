package main

import (
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
	redisDouble.Del("user:j")
	redisDouble.Del("peer:foo")
	redisDouble.Del("peer:bar")
}
