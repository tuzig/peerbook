package main

import (
	"github.com/gomodule/redigo/redis"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestReadDoc(t *testing.T) {
	startTest(t)
	redisDouble.HSet("peer:foobar", "name", "foo")
	exists, err := redis.Bool(redisConn.Do("EXISTS", "peer:foobar"))
	require.Nil(t, err)
	require.True(t, exists)
	var pd DBPeer
	err = readDoc("peer:foobar", &pd)
	require.Nil(t, err)
	require.Equal(t, "foo", pd.Name)
}
