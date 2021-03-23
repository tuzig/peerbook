package main

import (
	"fmt"
	"github.com/gomodule/redigo/redis"
)

// DBPeer is the info we store at redis
type DBPeer struct {
	User string `redis:"user"`
	FP   string `redis:"fp"`
	Name string `redis:"name"`
	Kind string `redis:"kind"`
}

var redisConn redis.Conn

func redisConnect(host string) error {
	rc, err := redis.Dial("tcp", host)
	if err == nil {
		redisConn = rc
	}
	return err
}

// readDoc reads a doc based on key into target
func readDoc(key string, target interface{}) error {
	// next 4 lines are about the peer doc AKA `pd` from redis
	values, err := redis.Values(redisConn.Do("HGETALL", key))

	if err = redis.ScanStruct(values, target); err != nil {
		return fmt.Errorf("Failed to scan peer %q: %w", key, err)
	}
	return nil
}
