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
type DBPeerList []*DBPeer

// DBPeer is the info we store about a peer in redis
type DBPeer struct {
	FP          string `redis:"fp" json:"fp"`
	Name        string `redis:"name" json:"name,omitempty"`
	User        string `redis:"user" json:"user,omitempty"`
	Kind        string `redis:"kind" json:"kind,omitempty"`
	Verified    bool   `redis:"verified" json:"verified,omitempty"`
	CreatedOn   int64  `redis:"created_on" json:"created_on,omitempty"`
	VerifiedOn  int64  `redis:"verified_on" json:"verified_on,omitempty"`
	LastConnect int64  `redis:"last_connect" json:"last_connect,omitempty"`
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

// GetToken reads the value of a token
func (d *DBType) GetToken(token string) (string, error) {
	key := fmt.Sprintf("token:%s", token)
	value, err := redis.String(d.conn.Do("GET", key))
	if err != nil {
		return "", fmt.Errorf("Failed to read token: %w:", err)
	}
	return value, nil
}

// GetPeer gets a peer, using the hub as cache for connected peers
func (d *DBType) GetPeer(fp string) (*DBPeer, error) {
	peer, found := hub.peers[fp]
	if found {
		return &peer.DBPeer, nil
	}
	key := fmt.Sprintf("peer:%s", fp)
	var pd DBPeer
	err := db.getDoc(key, &pd)
	if err != nil {
		return nil, err
	}
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
		p, err := d.GetPeer(fp)
		if err != nil {
			Logger.Warnf("Failed to read peer: %w", err)
		} else {
			l = append(l, p)
		}
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
	// add to the user's list
	key = fmt.Sprintf("user:%s", peer.User)
	db.conn.Do("SADD", key, peer.FP)
	return nil
}
func (p *DBPeer) Key() string {
	return fmt.Sprintf("peer:%s", p.FP)
}

// Verify grants or revokes authorization from a peer
func (p *DBPeer) Verify(v bool) {
	peer, found := hub.peers[p.FP]
	if v {
		db.conn.Do("HSET", p.Key(), "verified", "1")
		if found {
			peer.Send(StatusMessage{200, "You've been authorized"})
			peer.Verified = true
		}
	} else {
		db.conn.Do("HSET", p.Key(), "verified", "0")
		if found {
			peer.sendStatus(401, fmt.Errorf("Your verification was revoked"))
			peer.Verified = false
			if peer.ws != nil {
				peer.ws.Close()
			}
		}
	}
}
