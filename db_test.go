package main

import (
	"github.com/gomodule/redigo/redis"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGetPeer(t *testing.T) {
	startTest(t)
	redisDouble.HSet("peer:foo", "name", "fucked up")
	exists, err := redis.Bool(db.conn.Do("EXISTS", "peer:foo"))
	require.Nil(t, err)
	require.True(t, exists)
	pd, err := db.GetPeer("foo")
	require.Nil(t, err)
	require.Equal(t, "fucked up", pd.Name)
}
func TestGetUserList(t *testing.T) {
	startTest(t)
	redisDouble.HSet("peer:foo", "name", "fucked up", "user", "j")
	redisDouble.HSet("peer:bar", "name", "behind a. recognition", "user", "j")
	redisDouble.RPush("user:j", "foo", "bar")
	list, err := db.GetUserPeers("j")
	require.Nil(t, err)
	require.Equal(t, "fucked up", (*list)[0]["name"])
	require.Equal(t, "behind a. recognition", (*list)[1]["name"])
}
