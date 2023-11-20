package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mattn/go-sixel"
	"github.com/pquerna/otp/totp"
)

type UsersAuth struct {
	rcURL string
}

// NewUsersAuth creates a new UsersAuth
func NewUsersAuth() *UsersAuth {
	return &UsersAuth{}
}

func isUIDActive(uid string, rcURL string) (bool, error) {

	type Subscription map[string]json.RawMessage
	type Subscriber struct {
		Subscriptions map[string]Subscription `json:"subscriptions"`
	}
	type RCData struct {
		Subscriber Subscriber `json:"subscriber"`
	}
	// check if the uid is cached in redis
	subscribed, err := db.IsSubscribed(uid)
	if err != nil {
		return false, fmt.Errorf("Error checking if uid subscribed: %s", err)
	}
	if subscribed {
		return true, nil
	}
	var data RCData
	// getting the expires_date from the suscription
	url := fmt.Sprintf("%s/v1/subscribers/%s", rcURL, url.QueryEscape(uid))

	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("accept", "application/json")
	apiKey := os.Getenv("REVENUECAT_API_KEY")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", apiKey))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("Error getting isUIDActive from revenuecat: %s", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		return false, fmt.Errorf("Error getting isUIDActive from revenuecat: %s body: %s", res.Status, body)
	}
	Logger.Debugf("got revenurecat response: ", string(body))
	err = json.Unmarshal([]byte(body), &data)
	if err != nil {
		return false, fmt.Errorf("Error parsing revenurecat JSON: %s\n%s", err, body)
	}
	currentTime := time.Now().UTC()
	layout := "2006-01-02T15:04:05Z"
	for key := range data.Subscriber.Subscriptions {
		if !strings.Contains(key, "peerbook") {
			continue
		}
		var expires_date string
		err := json.Unmarshal(data.Subscriber.Subscriptions[key]["expires_date"], &expires_date)
		if err != nil {
			Logger.Warnf("Error parsing subscriber data: %s", err)
			Logger.Warnf("--> body:", body)
			continue
		}
		if expires_date == "" {
			continue
		}
		Logger.Debugf("expires_date: %s now %s", expires_date, currentTime.Format(layout))
		date, err := time.Parse(layout, expires_date)
		if err != nil {
			return false, fmt.Errorf("Error parsing date: %s", err)
		}
		if currentTime.Before(date) {
			err = db.SetSubscribed(uid)
			if err != nil {
				Logger.Warnf("Error setting uid as subscribed: %s", err)
			}
			return true, nil
		}
	}
	return false, nil
}

// IsAuthorized is called by the http handler to checks if a peer is
// authorized.
// Returns true if any of the tokens
// are authorized.
func (a *UsersAuth) IsAuthorized(tokens ...string) bool {
	rcURL := a.rcURL
	if rcURL == "" {
		rcURL = os.Getenv("REVENUECAT_URL")
		if rcURL == "" {
			rcURL = "https://api.revenuecat.com"
		}
	}
	if len(tokens) >= 2 && tokens[1] != "" {
		bearer := tokens[1]
		active, err := isUIDActive(bearer, rcURL)
		Logger.Debugf("checked if bearer exists: %s %b", bearer, active)
		if err != nil {
			Logger.Errorf("error checking if temp id is active %s", err)
			return false
		}
		if active {
			return true
		}
	}
	fp := tokens[0]
	peer, err := GetPeer(fp)
	if err != nil {
		Logger.Warnf("error getting peer %s: %s", fp, err)
	}
	if peer != nil && peer.Verified {
		active, err := isUIDActive(peer.User, rcURL)
		if err != nil {
			Logger.Warnf("error checking if uid is active %s", err)
			return false
		}
		return active
	}
	return false
}

func GetQRImage(user string) (string, error) {
	var qr bytes.Buffer
	ok, err := getUserKey(user)
	if err != nil {
		return "", fmt.Errorf("Failed to get users secret key QR iomage: %S", err)
	}
	img, err := ok.Image(200, 200)
	if err != nil {
		return "", fmt.Errorf("Failed to get the QR image: %S", err)
	}
	encoder := base64.NewEncoder(base64.StdEncoding, &qr)
	defer encoder.Close()
	png.Encode(encoder, img)
	return qr.String(), nil
}

func GetQRSixel(user string) (string, error) {
	var qr bytes.Buffer
	ok, err := getUserKey(user)
	if err != nil {
		return "", fmt.Errorf("Failed to get users secret key QR iomage: %S", err)
	}
	img, err := ok.Image(200, 200)
	if err != nil {
		return "", fmt.Errorf("Failed to get the QR image: %S", err)
	}
	sixel.NewEncoder(&qr).Encode(img)
	return qr.String(), nil
}

// serveAuthorize handles the authorization of a peer
// it will return a 200 if the peer is authorized
func serveAuthorize(w http.ResponseWriter, r *http.Request) {
	i := strings.IndexRune(r.URL.Path[1:], '/')
	t := r.URL.Path[i+2:]
	fp, err := url.PathUnescape(t)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Failed to unescape token: err: %s", err)))
		return
	}
	// check the fingerprint is in the db
	exists, err := db.PeerExists(fp)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("fingerprint is not known"))
		return
	}
	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("fingerprint is not known"))
		return
	}
	err = VerifyPeer(fp, true)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed to verify peer - %s", err)))
		return
	}
}

func register(fp string, email string, peerName string) (map[string]string, error) {
	Logger.Debugf("Got register cmd: %s %s", email, peerName)
	uID, err := db.GetUID4FP(fp)
	Logger.Debugf("got uid %q for %q", uID, fp)
	ret := map[string]string{}
	if uID == "" {
		// create the user and the peer
		uID, err = GenerateUser(email)
		if err != nil {
			return ret, fmt.Errorf("Failed to generate user: %s", err)
		}
		peer := NewPeer(fp, peerName, uID, "terminal7")
		err = db.AddPeer(peer)
		if err != nil {
			return ret, fmt.Errorf("Failed to add peer: %s", err)
		}
	}
	Logger.Debugf("before generating sixel: %s", uID)
	sixel, err := GetQRSixel(uID)
	if err != nil {
		return ret, fmt.Errorf("failed to generate QR code - %s", err)
	}
	ret["QR"] = sixel
	ret["ID"] = uID
	// turn into a string
	return ret, nil
}
func verify(fp string, target string, otp string) error {
	// get the uid of the admin
	uID, err := db.GetUID4FP(fp)
	if err != nil {
		return fmt.Errorf("failed to get user id - %s", err)
	}
	// validate the OTP
	s, err := db.getUserSecret(uID)
	if err != nil {
		return fmt.Errorf("failed to get user secret - %s", err)
	}
	if s == "" {
		return fmt.Errorf("failed to get user secret")
	}
	if !totp.Validate(otp, s) {
		Logger.Debug("Verify cmd got bad otp")
		return fmt.Errorf("Invalid OTP")
	}
	// check the fingerprint is in the db
	exists, err := db.PeerExists(target)
	if err != nil {
		return fmt.Errorf("failed to check peer exists - %s", err)
	}
	if !exists {
		peer := NewPeer(target, "", uID, "webexec")
		peer.Verified = true
		err = db.AddPeer(peer)
		if err != nil {
			return fmt.Errorf("failed to add peer - %s", err)
		}
	} else {
		peer, err := GetPeer(target)
		if err != nil {
			return fmt.Errorf("failed to get peer - %s", err)
		}
		if peer == nil {
			return fmt.Errorf("failed to get client's peer")
		}
		if peer.User != uID {
			return fmt.Errorf("target peer is not owned by client")
		}
		err = VerifyPeer(target, true)
		if err != nil {
			return fmt.Errorf("failed to verify peer - %s", err)
		}
	}
	Logger.Debugf("Verified peer: %s", target)
	err = db.SetQRVerified(uID)
	if err != nil {
		return fmt.Errorf("Failed to set user's QR as verified: %s", err)
	}
	err = db.SetSubscribed(uID)
	if err != nil {
		return fmt.Errorf("Failed to set user as subscribed: %s", err)
	}
	return nil
}
func deletePeer(fp string, target string, otp string) error {
	sameUser, err := db.IsSameUser(fp, target)
	if err != nil {
		return fmt.Errorf("failed to check if user with fingerprint %s and target %s are same - %s", fp, target, err)
	}
	if !sameUser {
		return fmt.Errorf("target %s does not belong to the user with fingerprint %s", target, fp)
	}
	peer, err := GetPeer(target)
	if err != nil {
		return fmt.Errorf("failed to get peer for target %s - %s", target, err)
	}
	if peer == nil {
		return fmt.Errorf("failed to get peer for target %s", target)
	}
	// validate the OTP
	s, err := db.getUserSecret(peer.User)
	if err != nil {
		return fmt.Errorf("failed to get user secret for user %s - %s", peer.User, err)
	}
	if s == "" {
		return fmt.Errorf("failed to get user secret for user %s", peer.User)
	}
	if totp.Validate(otp, s) {
		err = db.DeletePeer(target)
		if err != nil {
			return fmt.Errorf("failed to delete peer target %s - %s", target, err)
		}
	} else {
		return fmt.Errorf("invalid OTP for user %s", peer.User)
	}
	return nil
}
func ping(fp string, otp string) (string, error) {
	if otp == "" {
		uID, err := db.GetUID4FP(fp)
		if err != nil {
			Logger.Debugf("+-> failed to get user id - %s", err)
		} else {
			Logger.Debugf("+-> got user id %s", uID)
		}
		if err != nil || uID == "" {
			uID = "TBD"
		}
		Logger.Debugf("+-> returning %s", uID)
		return uID, nil
	}
	// check the fingerprint is in the db
	exists, err := db.PeerExists(fp)
	if err != nil {
		return "", fmt.Errorf("failed to check peer exists - %s", err)
	}
	if !exists {
		return "", fmt.Errorf("peer does not exist")
	}
	peer, err := GetPeer(fp)
	if err != nil {
		return "", fmt.Errorf("failed to get peer - %s", err)
	}
	if peer == nil {
		return "", fmt.Errorf("failed to get peer")
	}
	// validate the OTP
	s, err := db.getUserSecret(peer.User)
	if err != nil {
		return "", fmt.Errorf("failed to get user secret - %s", err)
	}
	if s == "" {
		return "", fmt.Errorf("failed to get user secret")
	}
	if !totp.Validate(otp, s) {
		return "", fmt.Errorf("invalid OTP")
	}
	err = VerifyPeer(fp, true)
	return "1", err
}
func rename(fp string, target string, name string) error {
	// TODO: optimize this as IsSameUser already gets the peer
	// check both fp and target belong to the same user
	sameUser, err := db.IsSameUser(fp, target)
	if err != nil {
		return fmt.Errorf("failed to check same user - %s", err)
	}
	if !sameUser {
		return fmt.Errorf("target does not belong to the user")
	}
	err = db.RenamePeer(target, name)
	if err != nil {
		return fmt.Errorf("failed to update peer - %s", err)
	}
	// send peer_update message
	// publish the peer update
	rc := db.pool.Get()
	defer rc.Close()
	peer, err := GetPeer(target)
	err = SendPeerUpdate(rc, peer.User, peer.FP, peer.Verified, peer.Online, peer.Name)
	if err != nil {
		return fmt.Errorf("failed to send peer update - %s", err)
	}
	return nil
}

func forwardSDP(fp string, target string, typ string, sdp json.RawMessage) error {
	exists, err := db.PeerExists(fp)
	if err != nil {
		return fmt.Errorf("failed to check peer exists - %s", err)
	}
	if !exists {
		return fmt.Errorf("peer does not exist")
	}
	targetPeer, err := GetPeer(target)
	if err != nil {
		return fmt.Errorf("failed to get target peer - %s", err)
	}
	sourcePeer, err := GetPeer(fp)
	if err != nil {
		return fmt.Errorf("failed to get source peer - %s", err)
	}
	if targetPeer == nil || sourcePeer == nil {
		return fmt.Errorf("failed to get peer")
	}
	if !targetPeer.Verified || !sourcePeer.Verified {
		return fmt.Errorf("peers are not verified")
	}
	if targetPeer.User != sourcePeer.User {
		return fmt.Errorf("peers are not owned by the same user")
	}
	// rc.Do("HSET", key, "last_connect", time.Now().Unix())
	msg := map[string]interface{}{
		"source_fp": fp,
		typ:         sdp,
	}
	return SendMessage(target, msg)
}

// GenerateUserID generates a random user id
func GenerateUser(email string) (string, error) {
	bytes := make([]byte, 10)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	uID := base32.StdEncoding.EncodeToString(bytes)
	return uID, db.AddUser(email, uID)
}

func GetPeersMessage(user string) (interface{}, error) {
	ps, err := GetUsersPeers(user)
	if err != nil {
		return nil, fmt.Errorf("Failed to get peer list: %w", err)
	}

	msg := map[string]interface{}{"uid": user}
	if ps != nil && len(*ps) > 0 {
		msg["peers"] = ps
	} else {
		msg["peers"] = []string{}
	}
	return msg, nil
}
