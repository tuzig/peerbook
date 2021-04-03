package main

import (
	"fmt"

	"github.com/alicebob/miniredis/v2"
	"github.com/gomodule/redigo/redis"
)

// DBType is the type that holds our db
type DBType struct {
	conn redis.Conn
}

// DBUser is the info we store about a user - a list of peers' fingerprint
type DBUser []string
type DBPeerList []map[string]string

// DBPeer is the info we store about a peer in redis
type DBPeer struct {
	User     string `redis:"user"`
	FP       string `redis:"fp"`
	Name     string `redis:"name"`
	Kind     string `redis:"kind"`
	Verified bool   `redis:"verified"`
}

// for testing we use a redis "double"
var redisDouble *miniredis.Miniredis

func (d *DBType) Connect(host string) error {
	// should we use mock redis?
	if redisDouble != nil {
		host = redisDouble.Addr()
	}
	rc, err := redis.Dial("tcp", host)
	if err == nil {
		d.conn = rc
	}
	return err
}

// GetPeer gets a peer, using the hub as cache for connected peers
func (d *DBType) GetPeer(fp string) (*DBPeer, error) {
	peer, found := hub.peers[fp]
	if found {
		return &peer.DBPeer, nil
	}
	key := fmt.Sprintf("peer:%s", fp)
	var pd DBPeer
	db.getDoc(key, &pd)
	return &pd, nil
}

// GetUser gets a user from redis
func (d *DBType) GetUser(email string) (*DBUser, error) {
	var r DBUser
	key := fmt.Sprintf("user:%s", email)
	values, err := redis.Values(d.conn.Do("SMEMBERS", key))
	if err != nil {
		return nil, fmt.Errorf("Failed to read user %q list: %w", email, err)
	}
	for _, fp := range values {
		r = append(r, string(fp.([]byte)))
	}
	Logger.Infof("returning: %v", r)
	return &r, nil
}
func (d *DBType) getDoc(key string, target interface{}) error {
	values, err := redis.Values(d.conn.Do("HGETALL", key))
	if err = redis.ScanStruct(values, target); err != nil {
		return fmt.Errorf("Failed to scan peer %q: %w", key, err)
	}
	return nil
}
func (d *DBType) PeerExists(fp string) (bool, error) {
	key := fmt.Sprintf("peer:%s", fp)
	return redis.Bool(db.conn.Do("EXISTS", key))
}
func (d *DBType) GetUserPeers(email string) (*DBPeerList, error) {
	var l DBPeerList
	u, err := d.GetUser(email)
	Logger.Infof("got back user: %v", u)
	if err != nil {
		return nil, err
	}
	for _, fp := range *u {
		i, err := d.GetPeer(fp)
		if err != nil {
			return nil, fmt.Errorf("Failed to read peer: %w", err)
		}
		l = append(l, map[string]string{
			"name": i.Name,
			"kind": i.Kind,
			"fp":   i.FP})
	}
	return &l, nil
}
func (d *DBType) Close() error {
	return d.conn.Close()
}
func (d *DBType) AddPeer(peer *Peer) error {
	key := fmt.Sprintf("peer:%s", peer.FP)
	exists, err := db.PeerExists(peer.FP)
	if err != nil {
		return err
	}
	if !exists {
		_, err := d.conn.Do("HSET", redis.Args{}.Add(key).AddFlat(peer.DBPeer)...)
		if err != nil {
			return err
		}
	}
	key = fmt.Sprintf("user:%s", peer.User)
	db.conn.Do("SADD", key, peer.FP)
	return nil
}
