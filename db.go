package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gomodule/redigo/redis"
)

const TokenLen = 30  // in Bytes, four times that in base64 and urls
const TokenTTL = 300 // in Seconds
// DBType is the type that holds our db
type DBType struct {
	pool *redis.Pool
}

// DBUser is the info we store about a user - a list of peers' fingerprint
type DBUser []string

// for testing we use a redis "double"
var redisDouble *miniredis.Miniredis

// CreateToken creates a short-live token to be emailed to the user
func (d *DBType) CreateToken(email string) (string, error) {
	if email == "" {
		return "", fmt.Errorf("Failied to create a token for an empty email")
	}
	b := make([]byte, TokenLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.StdEncoding.EncodeToString(b)
	key := fmt.Sprintf("token:%s", token)
	conn := d.pool.Get()
	defer conn.Close()
	_, err := conn.Do("SETEX", key, TokenTTL, email)
	if err != nil {
		Logger.Errorf("Failed to set token: %w", err)
	}
	return token, nil
}
func (d *DBType) Connect(host string) error {
	// should we use mock redis?
	if redisDouble != nil {
		host = redisDouble.Addr()
	}
	d.pool = &redis.Pool{
		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,
		Dial:        func() (redis.Conn, error) { return redis.Dial("tcp", host) },
	}
	return nil
}

// GetToken reads the value of a token
func (d *DBType) GetToken(token string) (string, error) {
	key := fmt.Sprintf("token:%s", token)
	conn := d.pool.Get()
	defer conn.Close()
	value, err := redis.String(conn.Do("GET", key))
	if err != nil {
		return "", fmt.Errorf("Failed to read token: %w:", err)
	}
	return value, nil
}

// GetUser gets a user from redis
func (d *DBType) GetUser(email string) (*DBUser, error) {
	var r DBUser
	key := fmt.Sprintf("user:%s", email)
	conn := d.pool.Get()
	defer conn.Close()
	values, err := redis.Values(conn.Do("SMEMBERS", key))
	if err != nil {
		return nil, fmt.Errorf("Failed to read user %q list: %w", email, err)
	}
	for _, fp := range values {
		r = append(r, string(fp.([]byte)))
	}
	return &r, nil
}
func (d *DBType) getDoc(key string, target interface{}) error {
	conn := d.pool.Get()
	defer conn.Close()
	values, err := redis.Values(conn.Do("HGETALL", key))
	if err = redis.ScanStruct(values, target); err != nil {
		return fmt.Errorf("Failed to scan peer %q: %w", key, err)
	}
	return nil
}
func (d *DBType) PeerExists(fp string) (bool, error) {
	key := fmt.Sprintf("peer:%s", fp)
	conn := d.pool.Get()
	defer conn.Close()
	return redis.Bool(conn.Do("EXISTS", key))
}
func (d *DBType) Close() error {
	return nil
	// return d.conn.Close()
}
func (d *DBType) AddPeer(peer *Peer) error {
	key := fmt.Sprintf("peer:%s", peer.FP)
	exists, err := db.PeerExists(peer.FP)
	if err != nil {
		return err
	}
	conn := d.pool.Get()
	defer conn.Close()
	if !exists {
		_, err := conn.Do("HSET", redis.Args{}.Add(key).AddFlat(peer)...)
		if err != nil {
			return err
		}
	}
	// add to the user's list
	key = fmt.Sprintf("user:%s", peer.User)
	conn.Do("SADD", key, peer.FP)
	return nil
}

// IsVerfied tests the db to see if a peer is verfied
func IsVerified(fp string) (bool, error) {
	key := fmt.Sprintf("peer:%s", fp)
	conn := db.pool.Get()
	defer conn.Close()
	return redis.Bool(conn.Do("HGET", key, "verified"))
}

// GetPeer gets a peer, using the hub as cache for connected peers
func GetPeer(fp string) (*Peer, error) {
	key := fmt.Sprintf("peer:%s", fp)
	var pd Peer
	err := db.getDoc(key, &pd)
	if err != nil {
		return nil, err
	}
	return &pd, nil
}
func VerifyPeer(fp string, v bool) {
	rc := db.pool.Get()
	defer rc.Close()
	key := fmt.Sprintf("peer:%s", fp)
	c, connected := hub.conns[fp]
	if connected {
		c.Verified = v
	}
	if v {
		rc.Do("HSET", key, "verified", "1")
		if connected {
			c.Send(StatusMessage{200, "peer is verified"})
			Logger.Infof("Sent a 200 to a newly verified peer")
		} else {
			Logger.Infof("Verified an offline peer")
		}
	} else {
		rc.Do("HSET", key, "verified", "0")
		if connected {
			c.sendStatus(401, fmt.Errorf("peer's verification was revoked"))
		}
	}
}
