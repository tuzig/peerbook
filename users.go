package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/kr/pty"
)

type UsersAuth struct {
}

// NewUsersAuth creates a new UsersAuth
func NewUsersAuth() *UsersAuth {
	return &UsersAuth{}
}

func (a *UsersAuth) IsAuthorized(tokens []string) bool {
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

// serveRegister handles the registration of a new user
// it will return a 200 if the user is registered
// it will get a json encoded user witht the following fields:
// - email
// - temp_id
// - peer_name
// - fp
// - public_key
// If will allocate a random permenet ID for the user and
// store it and the email in the db. It will add a new peer
// fith the fp & public key and return 200 with the following fields:
// - QR
// - ID
// - token
func serveRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// get the json body
	// check the body has the correct fields
	// check the temp_id is in the db
	// check the email is not in the db
	// check the fingerprint is not in the db
	// check the public key is not in the db
	// generate a random permenent ID
	defer r.Body.Close()
	// get the fields from the body to a map
	var m map[string]string
	err := json.NewDecoder(r.Body).Decode(&m)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// check the map has the correct fields
	// check the temp_id is in the db
	// check the email is not in the db
	// check the fingerprint is not in the db
	if _, ok := m["email"]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("email is missing"))
		return
	}
	if _, ok := m["temp_id"]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("temp_id is missing"))
		return
	}
	if _, ok := m["fp"]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("fp is missing"))
		return
	}
	if _, ok := m["public_key"]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("public_key is missing"))
		return
	}
	if _, ok := m["peer_name"]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("peer_name is missing"))
		return
	}
	// check the temp_id is in the db
	exists, err := db.tempIDExists(m["temp_id"])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed to check temp_id - %s", err)))
		return
	}
	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("temp_id is not known"))
		return
	}
	// add the user
	// generate a random permenent ID
	// add the user to the db
	uID, err := db.AddUser(m["email"])
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to add user - %s", err),
			http.StatusInternalServerError)
		return
	}
	peer := NewPeer(m["fp"], m["peer_name"], uID, "client", m["public_key"])
	peer.Verified = true
	err = db.AddPeer(peer)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to add peer - %s", err),
			http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	next, err := createTempURL(uID, "qr", true)
	// write a json encoded response with the following fields:
	// - QR
	// - ID
	// - token
	img, err := GetQRImage(uID)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate QR code - %s", err),
			http.StatusInternalServerError)
		return
	}
	resp := map[string]string{
		// TODO: add the QR code
		"QR":       img,
		"ID":       uID,
		"next_url": next,
	}
	json.NewEncoder(w).Encode(resp)
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
func RunCommand(command []string, env map[string]string, ws *pty.Winsize, pID int, fp string) (*exec.Cmd, *os.File, error) {
	return nil, nil, nil
}
