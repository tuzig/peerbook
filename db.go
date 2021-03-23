package main

import (
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
