package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gomodule/redigo/redis"
	"github.com/pquerna/otp/totp"
)

const TokenLen = 30          // in Bytes, four times that in base64 and urls
const TokenTTL = 300         // in Seconds
const SubscriberTTL = 3 * 60 // in Seconds
const EmailInterval = 60     // in Seconds
const MaxPeersPerUser = 20
const UserIDLength = 10

// errTooManyPeers is an error that is returned when a user has too many peers
var ErrTooManyPeers = fmt.Errorf("User has too many peers")

// DBType is the type that holds our db
type DBType struct {
	pool  *redis.Pool
	poolM sync.Mutex
}

// DBUser is the info we store about a user - a list of peers' fingerprint
type DBUser []string

// for testing we use a redis "double"
var redisDouble *miniredis.Miniredis

// RandomString generates a random string of n bytes
func RandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// email creates a short-live token to be emailed to the user
func (d *DBType) CreateToken(uid string) (string, error) {
	if uid == "" {
		return "", fmt.Errorf("Failed to create a token for an empty uid")
	}
	token := RandomString(TokenLen)
	key := fmt.Sprintf("token:%s", token)
	conn := d.getConn()
	defer conn.Close()
	_, err := conn.Do("SETEX", key, TokenTTL, uid)
	if err != nil {
		return "", fmt.Errorf("Failed to set token: %w", err)
	}
	return token, nil
}
func (d *DBType) Connect(host string) error {
	// should we use mock redis?
	if redisDouble != nil {
		host = redisDouble.Addr()
	}
	d.poolM.Lock()
	d.pool = &redis.Pool{
		MaxIdle:     5,
		IdleTimeout: 5 * time.Second,
		Dial:        func() (redis.Conn, error) { return redis.Dial("tcp", host) },
	}
	d.poolM.Unlock()
	if redisDouble == nil {
		conn := d.getConn()
		defer conn.Close()
		_, err := conn.Do("GET", "SFJAWERWEQRQWER")
		if err != redis.ErrNil {
			return err
		}
	}
	return nil
}

// GetToken reads the value of a token, usually an email address
func (d *DBType) GetToken(token string) (string, error) {
	key := fmt.Sprintf("token:%s", token)
	conn := d.getConn()
	defer conn.Close()
	value, err := redis.String(conn.Do("GET", key))
	if err != nil {
		return "", fmt.Errorf("Failed to read token: %w:", err)
	}
	return value, nil
}

// GetPeers gets a user from redis
func (d *DBType) GetPeers(uid string) (*DBUser, error) {
	var r DBUser
	key := fmt.Sprintf("userset:%s", uid)
	conn := d.getConn()
	defer conn.Close()
	values, err := redis.Values(conn.Do("SMEMBERS", key))
	if err != nil {
		return nil, fmt.Errorf("Failed to read user %q list: %w", uid, err)
	}
	for _, fp := range values {
		r = append(r, string(fp.([]byte)))
	}
	return &r, nil
}
func (d *DBType) getDoc(key string, target interface{}) error {
	conn := d.getConn()
	defer conn.Close()
	values, err := redis.Values(conn.Do("HGETALL", key))
	if err = redis.ScanStruct(values, target); err != nil {
		return fmt.Errorf("Failed to scan peer %q: %w", key, err)
	}
	return nil
}
func (d *DBType) PeerExists(fp string) (bool, error) {
	key := fmt.Sprintf("peer:%s", fp)
	conn := d.getConn()
	defer conn.Close()
	return redis.Bool(conn.Do("EXISTS", key))
}
func (d *DBType) Close() error {
	return nil
	// return d.conn.Close()
}

// SetPeerUser sets a peer's user
func (d *DBType) SetPeerUser(fp string, user string) error {
	peerKey := fmt.Sprintf("peer:%s", fp)
	conn := d.pool.Get()
	defer conn.Close()
	Logger.Infof("Setting peer %q user to %q", fp, user)
	_, err := conn.Do("HSET", peerKey, "user", user, "verified", "0")
	if err != nil {
		return fmt.Errorf("Failed to set peer %q user: %w", fp, err)
	}
	// add the peer to the user's set
	setKey := fmt.Sprintf("userset:%s", user)
	_, err = conn.Do("SADD", setKey, fp)
	if err != nil {
		return fmt.Errorf("Failed to set peer %q user: %w", fp, err)
	}
	peer, err := GetPeer(fp)
	if err != nil {
		return fmt.Errorf("Failed to get peer %q name: %w", fp, err)
	}
	return SendPeerUpdate(conn, user, fp, false, peer.Online, peer.Name)
}

func (d *DBType) RenamePeer(fp string, name string) error {
	key := fmt.Sprintf("peer:%s", fp)
	conn := d.pool.Get()
	defer conn.Close()
	_, err := conn.Do("HSET", key, "name", name)
	if err != nil {
		return fmt.Errorf("Failed to set peer %q user: %w", fp, err)
	}
	return nil
}

// AddPeer adds or updates a peer
func (d *DBType) AddPeer(peer *Peer) error {
	conn := d.getConn()
	defer conn.Close()
	if peer.User != "" {
		key := fmt.Sprintf("userset:%s", peer.User)
		values, err := redis.Values(conn.Do("SMEMBERS", key))
		if err != nil {
			return fmt.Errorf("Failed to read user %q list: %w", peer.User, err)
		}
		if len(values) == MaxPeersPerUser {
			return ErrTooManyPeers
		}
		for _, v := range values {
			// check if the peer's name already exists
			fp, err := redis.String(v, nil)
			if err != nil {
				return fmt.Errorf("Failed to convert peer %q: %w", v, err)
			}
			otherPeer, err := GetPeer(fp)
			if err != nil {
				return fmt.Errorf("Failed to get peer %q: %w", fp, err)
			}
			if otherPeer.Name == peer.Name {
				return fmt.Errorf("Peer name already exists")
			}
		}
		_, err = conn.Do("SADD", key, peer.FP)
		if err != nil {
			// get the key's kind
			kind, err := redis.String(conn.Do("TYPE", key))
			return fmt.Errorf("Failed to add peer - kind %q: %w", kind, err)
		}
	}
	_, err := conn.Do("HSET", redis.Args{}.Add(peer.Key()).AddFlat(peer)...)
	if err != nil {
		return fmt.Errorf("Failed to add peer %q: %w", peer.FP, err)
	}
	return nil
}

// IsVerfied tests the db to see if a peer is verfied
func IsVerified(fp string) bool {
	key := fmt.Sprintf("peer:%s", fp)
	conn := db.pool.Get()
	defer conn.Close()
	verified, err := redis.Bool(conn.Do("HGET", key, "verified"))
	if err != nil {
		return false
	}
	return verified
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

// VerifyPeer is a function that sets the peers verification and publishes
// it's new state to the user's channel
func VerifyPeer(fp string, verified bool) error {
	rc := db.pool.Get()
	defer rc.Close()
	key := fmt.Sprintf("peer:%s", fp)
	online, err := redis.Bool(rc.Do("HGET", key, "online"))
	if err != nil {
		online = false
	}
	if verified {
		_, err = rc.Do("HSET", key, "verified", "1")
	} else {
		_, err = rc.Do("HSET", key, "verified", "0")
	}
	if err != nil {
		return fmt.Errorf("Failed to set peer verification %s: %w", fp, err)
	}
	peer, err := GetPeer(fp)
	if err != nil {
		return fmt.Errorf("Failed to get peer %s: %w", fp, err)
	}
	// publish the peer's state
	return SendPeerUpdate(rc, peer.User, fp, verified, online, peer.Name)
}
func (d *DBType) canSendEmail(email string) bool {
	key := fmt.Sprintf("dontsend:%s", email)
	conn := d.getConn()
	defer conn.Close()
	blocked, err := redis.Bool(conn.Do("EXISTS", key))
	if err != nil {
		Logger.Warnf("failed to check if key %q exists", key)
		return false
	}
	if blocked {
		return false
	}
	_, err = conn.Do("SETEX", key, EmailInterval, "1")
	return true
}
func (d *DBType) SetQRVerified(uid string) error {
	key := fmt.Sprintf("user:%s", uid)
	conn := d.getConn()
	defer conn.Close()
	_, err := conn.Do("HSET", key, "QRVerified", "1")
	return err
}
func (d *DBType) getConn() redis.Conn {
	d.poolM.Lock()
	conn := d.pool.Get()
	d.poolM.Unlock()
	return conn
}
func (d *DBType) IsQRVerified(uid string) bool {
	key := fmt.Sprintf("user:%s", uid)
	conn := d.getConn()
	defer conn.Close()
	seen, err := redis.Bool(conn.Do("HGET", key, "QRVerified"))
	if err != nil {
		Logger.Warnf("failed to check if key %q exists", key)
		return false
	}
	if seen {
		return true
	}
	return false
}
func (d *DBType) Reset() {
	conn := d.getConn()
	i := 0
	for {
		arr, err := redis.Values(conn.Do("SCAN", i, "MATCH", "peer:*"))
		if err != nil {
			Logger.Errorf("Failed to retrieve redis keys: %s", err)
		}
		i, err = redis.Int(arr[0], nil)
		keys, err := redis.Strings(arr[1], nil)
		for _, k := range keys {
			if _, err := conn.Do("HSET", k, "online", false); err != nil {
				Logger.Errorf("Failed to set %s online to false: %s", k, err)
			}
		}
		if i == 0 {
			break
		}
	}
}
func (d *DBType) GetICEServers() ([]ICEServer, error) {
	var ret []ICEServer
	conn := d.getConn()
	keys, err := redis.Strings(conn.Do("KEYS", "iceserver:*"))
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve iceserver:* keys: %s", err)
	}
	for _, key := range keys {
		var info ICEServer
		d.getDoc(key, &info)
		if !info.Active {
			continue
		}
		ret = append(ret, info)
	}
	return ret, nil
}

func (d *DBType) IsSameUser(fp1 string, fp2 string) (bool, error) {
	uID1, err := db.GetUID4FP(fp1)
	if err != nil {
		return false, fmt.Errorf("failed to get user id - %s", err)
	}
	if uID1 == "" {
		return false, fmt.Errorf("failed to get user id")
	}
	uID2, err := db.GetUID4FP(fp2)
	if err != nil {
		return false, fmt.Errorf("failed to get user id - %s", err)
	}
	if uID2 == "" {
		return false, fmt.Errorf("failed to get user id")
	}
	return uID1 == uID2, nil
}

// DeletePeer deletes a peer from the database
func (d *DBType) DeletePeer(fp string) error {
	uID, err := d.GetUID4FP(fp)
	if err != nil {
		return fmt.Errorf("failed to get user id - %s", err)
	}
	key := fmt.Sprintf("peer:%s", fp)
	conn := d.pool.Get()
	defer conn.Close()
	_, err = conn.Do("SREM", fmt.Sprintf("userset:%s", uID), fp)
	if err != nil {
		return err
	}
	_, err = conn.Do("DEL", key)
	return err
}

// tempIDExists checks if a temporary ID exists
// it returns true if it does, false otherwise
// and an error if something went wrong
func (d *DBType) tempIDExists(id string) (bool, error) {
	key := fmt.Sprintf("tempid:%s", id)
	conn := d.pool.Get()
	defer conn.Close()
	exists, err := redis.Bool(conn.Do("EXISTS", key))
	if err != nil {
		return false, err
	}
	return exists, nil
}

// AddUser is used to add a new user to the data base
// it recieves the users eamil.
// If the user already exists, it returns the permanent user id
// and an error
func (d *DBType) AddUser(email string, uid string) error {
	conn := d.pool.Get()
	defer conn.Close()
	idkey := fmt.Sprintf("user:%s", uid)
	key := fmt.Sprintf("uid:%s", email)
	_, err := conn.Do("SET", key, uid)
	if err != nil {
		return fmt.Errorf("Failed to set %s: %w", key, err)
	}
	_, err = conn.Do("HSET", idkey, "email", email, "active", "1")
	if err != nil {
		return fmt.Errorf("Failed to set %s: %w", idkey, err)
	}
	return nil
}

// GetEmail returns the email of a user
func (d *DBType) GetEmail(uID string) (string, error) {
	key := fmt.Sprintf("user:%s", uID)
	conn := d.pool.Get()
	defer conn.Close()
	email, err := redis.String(conn.Do("HGET", key, "email"))
	if err != nil {
		return "", fmt.Errorf("Failed to get %s: %w", key, err)
	}
	return email, nil
}

// GetUID4FP returns the user id of a peer's fingerprint
func (d *DBType) GetUID4FP(fp string) (string, error) {
	key := fmt.Sprintf("peer:%s", fp)
	conn := d.pool.Get()
	defer conn.Close()
	uid, err := redis.String(conn.Do("HGET", key, "user"))
	if err != nil {
		return "", fmt.Errorf("Failed to get %s: %w", key, err)
	}
	return uid, nil
}

// GetUserID returns the user id of an email
func (d *DBType) GetUserID(email string) (string, error) {
	key := fmt.Sprintf("uid:%s", email)
	conn := d.pool.Get()
	defer conn.Close()
	id, err := redis.String(conn.Do("GET", key))
	if err != nil {
		return "", fmt.Errorf("Failed to get %s: %w", key, err)
	}
	return id, nil
}
func (d *DBType) RemoveTempID(tempID string) error {
	conn := d.pool.Get()
	defer conn.Close()
	key := fmt.Sprintf("tempid:%s", tempID)
	_, err := conn.Do("DEL", key)
	return err
}
func (d *DBType) AddTempID(tempID string) error {
	conn := d.pool.Get()
	defer conn.Close()
	key := fmt.Sprintf("tempid:%s", tempID)
	_, err := conn.Do("Set", key, "1")
	return err
	//  calculate how long the tempid should be valid for
	// ttl := expireAt/1000 - time.Now().Unix()
	// err = db.Expire(key, ttl)
}
func (d *DBType) SetUserActive(UserID string, active bool) error {
	conn := d.pool.Get()
	defer conn.Close()
	key := fmt.Sprintf("user:%s", UserID)
	_, err := conn.Do("HSET", key, "active", active)
	return err
}

// IsSubscribed returns true if the user is subscribed
func (d *DBType) IsSubscribed(UserID string) (bool, error) {
	conn := d.pool.Get()
	defer conn.Close()
	key := fmt.Sprintf("subscriber:%s", UserID)
	return redis.Bool(conn.Do("EXISTS", key))
}

// SetSubscribed sets the user as subscribed
func (d *DBType) SetSubscribed(UserID string) error {
	conn := d.pool.Get()
	defer conn.Close()
	key := fmt.Sprintf("subscriber:%s", UserID)
	_, err := conn.Do("SET", key, "1", "EX", SubscriberTTL)
	return err
}
func (d *DBType) getUserSecret(user string) (string, error) {
	var secret string
	conn := d.pool.Get()
	defer conn.Close()
	key := fmt.Sprintf("user:%s", user)
	secret, err := redis.String(conn.Do("HGet", key, "secret"))
	if err == redis.ErrNil {
		ok, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "PeerBook",
			AccountName: user,
		})
		if err != nil {
			return "", fmt.Errorf("Failed to generate a TOTP key: %s", err)
		}
		// all is well, save the secret
		secret = ok.Secret()
		_, err = conn.Do("HSET", key, "secret", secret)
		if err != nil {
			return "", fmt.Errorf("Failed to save the user's secret")
		}
	} else if err != nil {
		return "", err
	}
	return secret, nil
}

// RemoveUser removes a user and all his peers from the database
func (d *DBType) RemoveUser(uid string, peers PeerList) error {
	conn := d.pool.Get()
	defer conn.Close()
	email, err := db.GetEmail(uid)
	if err != nil {
		return fmt.Errorf("Failed to get email for user %q: %s", uid, err)
	}
	key := fmt.Sprintf("uid:%s", email)
	_, err = conn.Do("DEL", key)
	if err != nil {
		return fmt.Errorf("Failed to delete %s: %w", key, err)
	}
	key = fmt.Sprintf("user:%s", uid)
	_, err = conn.Do("DEL", key)
	if err != nil {
		return fmt.Errorf("Failed to delete user %q: %s", email, err)
	}
	for _, peer := range peers {
		key := fmt.Sprintf("peer:%s", peer.FP)
		_, err = conn.Do("DEL", key)
		if err != nil {
			return fmt.Errorf("Failed to delete peer %q: %s", peer.FP, err)
		}
	}
	key = fmt.Sprintf("userset:%s", uid)
	_, err = conn.Do("DEL", key)
	return nil
}
