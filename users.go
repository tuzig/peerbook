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
// authorized.
// Returns true if any of the tokens
// are authorized.
func (a *UsersAuth) IsAuthorized(tokens ...string) bool {
	if len(tokens) >= 2 {
		bearer := tokens[1]
		exists, err := db.tempIDExists(bearer)
		Logger.Debugf("checked if bearer exists: %s %b", bearer, exists)
		if err != nil {
			Logger.Error("error checking if temp id exists", err)
			return false
		}
		if exists {
			// token matched a temp id, so we can let the peer in, just this once
			return true
			//TODO: remove the temp id
			/*
				err = db.RemoveTempID(t)
				if err != nil {
					Logger.Error("error removing temp id", err)
				}
			*/
		}
	}
	fp := tokens[0]
	peer, err := GetPeer(fp)
	if err != nil {
		Logger.Warnf("error getting peer %s: %s", fp, err)
	}
	if peer != nil {
		return peer.Verified
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
		if err != nil {
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
		} else if uID == "" {
			uID, err = GenerateUser(email)
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to generate user: %s", err)
			}
			err = db.SetPeerUser(fp, uID)
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to add peer: %s", err)
			}
		} else {
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
		return nil, f, nil
	case "ping":
		// ping can be used to check if the server is alive
		// if given an argument, it assumes it'n an OTP and will
		// check it against the user's secret and will echo 0 if it's
		// valid and 1 if it's not
		if len(command) < 2 {
			uID, err := db.GetUID4FP(fp)
			if err != nil || uID == "" {
				uID = "TBD"
			}
			f := NewRWC([]byte(uID))
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
