package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/creack/pty"
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
		if !strings.HasPrefix(key, "peerbook") {
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

func RunCommand(command []string, env map[string]string, ws *pty.Winsize, pID int, fp string) (*exec.Cmd, io.ReadWriteCloser, error) {

	switch command[0] {
	case "register":
		email := command[1]
		peerName := command[2]
		Logger.Debugf("Got register cmd: %s %s", email, peerName)
		uID, err := db.GetUID4FP(fp)
		Logger.Debugf("got uid %q for %q", uID, fp)
		if uID == "" {
			// create the user and the peer
			uID, err = GenerateUser(email)
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to generate user: %s", err)
			}
			peer := NewPeer(fp, peerName, uID, "terminal7")
			err = db.AddPeer(peer)
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to add peer: %s", err)
			}
		}  else {
			Logger.Debugf("Peer %s already exists: %s", fp, uID)
		}
		Logger.Debugf("before generating sixel: %s", uID)
		sixel, err := GetQRSixel(uID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate QR code - %s", err)
		}
		resp := map[string]string{
			// TODO: add the QR code
			"QR": sixel,
			"ID": uID,
		}
		// turn into a string
		msg, err := json.Marshal(resp)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal json - %s", err)
		}
		Logger.Debugf("succesful registration with response: %s", msg)
		f := NewRWC(msg)
		return nil, f, nil
	case "verify":
		Logger.Debug("verifying peer")
		target := command[1]
		otp := command[2]
		// get the uid of the admin
		uID, err := db.GetUID4FP(fp)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get user id - %s", err)
		}
		// validate the OTP
		s, err := getUserSecret(uID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get user secret - %s", err)
		}
		if s == "" {
			return nil, nil, fmt.Errorf("failed to get user secret")
		}
		ret := "0"
		if !totp.Validate(otp, s) {
			Logger.Debug("Verify cmd got bad otp")
		} else {
			ret = "1"
		}
		f := NewRWC([]byte(ret))
		if ret == "0" {
			return nil, f, nil
		}
		// check the fingerprint is in the db
		exists, err := db.PeerExists(target)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to check peer exists - %s", err)
		}
		if !exists {
			peer := NewPeer(target, "", uID, "webexec")
			peer.Verified = true
			err = db.AddPeer(peer)
			if err != nil {
				return nil, nil, fmt.Errorf("peer does not exist")
			}
		} else {
			peer, err := GetPeer(target)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to get peer - %s", err)
			}
			if peer == nil {
				return nil, nil, fmt.Errorf("failed to get client's peer")
			}
			if peer.User != uID {
				return nil, nil, fmt.Errorf("target peer is not owned by client")
			}
			err = VerifyPeer(target, true)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to verify peer - %s", err)
			}
		}
		Logger.Debugf("Verified peer: %s", target)
		err = db.SetSubscribed(uID)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to set user as subscribed: %s", err)
		}
		return nil, f, nil
	case "ping":
		// ping can be used to check if the server is alive
		// if given an argument, it assumes it'n an OTP and will
		// check it against the user's secret and will echo 0 if it's
		// valid and 1 if it's not
		Logger.Debug("Got a ping")
		if len(command) < 2 {
			uID, err := db.GetUID4FP(fp)
			if err != nil {
				Logger.Debugf("+-> failed to get user id - %s", err)
			} else {
				Logger.Debugf("+-> got user id %s", uID)
			}
			if err != nil || uID == "" {
				uID = "TBD"
			}
			f := NewRWC([]byte(uID))
			Logger.Debugf("+-> returning %s", uID)
			return nil, f, nil
		}
		otp := command[1]
		// check the fingerprint is in the db
		exists, err := db.PeerExists(fp)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to check peer exists - %s", err)
		}
		if !exists {
			return nil, nil, fmt.Errorf("peer does not exist")
		}
		peer, err := GetPeer(fp)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get peer - %s", err)
		}
		if peer == nil {
			return nil, nil, fmt.Errorf("failed to get peer")
		}
		// validate the OTP
		s, err := getUserSecret(peer.User)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get user secret - %s", err)
		}
		if s == "" {
			return nil, nil, fmt.Errorf("failed to get user secret")
		}
		ret := "0"
		if totp.Validate(otp, s) {
			ret = "1"
			VerifyPeer(fp, true)
		}
		f := NewRWC([]byte(ret))
		return nil, f, err
	}
	Logger.Debugf("Got unknown command: %s", command)
	return nil, nil, fmt.Errorf("Unknown peerbook command")
}

type RWC struct {
	buffer []byte
}

func NewRWC(b []byte) *RWC {
	return &RWC{
		buffer: b,
	}
}
func (r *RWC) Read(p []byte) (n int, err error) {
	if len(r.buffer) == 0 {
		return 0, io.EOF
	}
	n = copy(p, r.buffer)
	r.buffer = r.buffer[n:]
	return n, nil
}
func (r *RWC) Write(p []byte) (n int, err error) {
	Logger.Debugf("got write to RWC: %s", p)
	return len(p), nil
}
func (r *RWC) Close() error {
	return nil
}

// GenerateUserID generates a 10 digit long, base 10 random user ID
func GenerateUser(email string) (string, error) {
	uID := strconv.Itoa(rand.Intn(9000000000) + 1000000000)
	return uID, db.AddUser(email, uID)
}
