package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"

	"github.com/creack/pty"
	"github.com/mattn/go-sixel"
	"github.com/pquerna/otp/totp"
)

type UsersAuth struct {
}

// NewUsersAuth creates a new UsersAuth
func NewUsersAuth() *UsersAuth {
	return &UsersAuth{}
}

// IsAuthorized is called by the http handler to checks if a peer is
// authorized. Accepts at least one token and assumes the first
// token is the fingerprint. returns true if any of the tokens
// are authorized.
func (a *UsersAuth) IsAuthorized(tokens ...string) bool {
	Logger.Debugf("checking if user is authorized: %v", tokens)
	for _, t := range tokens {
		exists, err := db.PeerExists(t)
		if err != nil {
			Logger.Error("error checking if peer exists", err)
			return false
		}
		if exists {
			return true
		}
		exists, err = db.tempIDExists(t)
		if err != nil {
			Logger.Error("error checking if temp id exists", err)
			return false
		}
		if exists {
			// The FP is the first token
			fp := tokens[0]
			Logger.Debugf("registering user with fp: %s", fp)
			peer := NewPeer(fp, "temp", "", "client")
			peer.Verified = true
			err = db.AddPeer(peer)
			if err != nil {
				Logger.Error("error registering user", err)
				return false
			}
			// remove the temp id
			err = db.RemoveTempID(t)
			if err != nil {
				Logger.Error("error removing temp id", err)
			}
			return true
		}
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
		uID := GenerateUserID()
		err = db.AddUser(email, uID)
		if uID == "" {
			return nil, nil, fmt.Errorf("failed to add/get a user - %s", err)
		}
		peer.SetUser(uID)
		peer.setName(peerName)
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
		Logger.Debugf("replying to register: %s", msg)
		f := NewRWC(msg)
		return nil, f, nil
	case "authorize":
		target := command[1]
		otp := command[2]
		// check the fingerprint is in the db
		exists, err := db.PeerExists(target)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to check peer exists - %s", err)
		}
		if !exists {
			return nil, nil, fmt.Errorf("peer does not exist")
		}
		peer, err := GetPeer(target)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get peer - %s", err)
		}
		// validate the OTP
		s, err := getUserSecret(peer.User)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get user secret - %s", err)
		}
		if s == "" {
			return nil, nil, fmt.Errorf("failed to get user secret")
		}
		if !totp.Validate(otp, s) {
			return nil, nil, fmt.Errorf("failed to validate OTP")
		}
		if peer == nil {
			return nil, nil, fmt.Errorf("failed to get peer")
		}
		err = VerifyPeer(target, true)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to verify peer - %s", err)
		}
		return nil, nil, nil
	case "ping":
		// ping can be used to check if the server is alive
		// if given an argument, it assumes it'n an OTP and will
		// check it against the user's secret and will echo 0 if it's
		// valid and 1 if it's not
		if len(command) < 2 {
			f := NewRWC([]byte("pong"))
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
		}
		f := NewRWC([]byte(ret))
		return nil, f, err
	}
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
	n = copy(p, r.buffer)
	r.buffer = r.buffer[n:]
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}
func (r *RWC) Write(p []byte) (n int, err error) {
	Logger.Debugf("got write to RWC: %s", p)
	return len(p), nil
}
func (r *RWC) Close() error {
	return nil
}

// GenerateUserID generates a 10 digit long random user ID
func GenerateUserID() string {
	// Generate 32 random bytes
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		// Handle error
	}

	// Encode the random bytes in base64
	base64Str := base64.StdEncoding.EncodeToString(randomBytes)

	// Get the first 20 characters of the base64 string and convert to integer
	first20Chars := base64Str[:20]
	userIDInt, err := strconv.ParseInt(first20Chars, 64, 0)
	if err != nil {
		// Handle error
	}

	// Convert the integer to a string
	userIDStr := strconv.Itoa(int(userIDInt))

	return userIDStr
}
