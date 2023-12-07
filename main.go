// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v3"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/tuzig/webexec/httpserver"
	"github.com/tuzig/webexec/peers"
	"go.uber.org/zap"
	"gopkg.in/gomail.v2" //go get gopkg.in/gomail.v2
)

const (
	// SendChanSize is the size of the send channel in messages
	SendChanSize = 4

	DefaultHomeURL       = "https://peerbook.io"
	DefaultRevenueCatURL = "https://api.revenuecat.com"
)

// Logger is our global logger
var (
	Logger *zap.SugaredLogger
	stop   chan os.Signal
	db     DBType
	hub    Hub
	//go:embed templates
	tFS embed.FS
)

// PeerIsForeign is an error for the time when a peer asks to connect to a peer
// belonging to another user
type PeerIsForeign struct {
	peer *Peer
}

func (e *PeerIsForeign) Error() string {
	return fmt.Sprintf("The target peer belong to a different user: %q", e.peer.User)
}

// UnauthorizedPeer is an error
type UnauthorizedPeer struct {
	FP string
}

func (e *UnauthorizedPeer) Error() string {
	return "Peer is not verified, blocking request"
}

// TargetNotFound is an error
type TargetNotFound struct {
	fp string
}

func (p *TargetNotFound) Error() string {
	return fmt.Sprintf("Target peer not found: %s", p.fp)
}

// PeerNotFound is an error containing the requested fingerprint
type PeerNotFound struct {
	fp string
}

func (p *PeerNotFound) Error() string {
	return fmt.Sprintf("Peer not found: %s", p.fp)
}

// PeerChanged is an error
type PeerChanged struct{}

type ListContext struct {
	Message string
	User    string
	Peers   *PeerList
	Clean   bool
}

func (p *PeerChanged) Error() string {
	return "Peer exists with different properties"
}

// FormatDateInt receives a unix timestamp and returns a formatted date
// example: 1612345678 -> 2021-02-03 04:05:06
func FormatDateInt(i int64) string {
	return time.Unix(i, 0).Format("2006-01-02 15:04:05")
}

// getStrFromEncodedPath It works assuming a valid token is the second
// part of the url path
func getStrFromEncodedPath(r *http.Request) (string, error) {
	path := r.URL.Path
	i := strings.IndexRune(path[1:], '/')
	t := path[i+2:]
	token, err := url.PathUnescape(t)
	if err != nil {
		return "", fmt.Errorf("Failed to unescape token: err: %w", err)
	}
	if token == "" {
		return "", nil
	}

	user, err := db.GetToken(token)
	if err != nil || user == "" {
		return "", fmt.Errorf("Failed to get token: err: %w", err)
	}
	return user, nil
}

func serveLogin(w http.ResponseWriter, r *http.Request) {
	// esnure it's a post request
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// get the json from the request body
	var req struct {
		User string `json:"user"`
		OTP  string `json:"otp"`
		FP   string `json:"fp"`
		Name string `json:"name"`
	}
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&req)
	if err != nil {
		http.Error(w, "Bad JSON", http.StatusBadRequest)
		return
	}
	Logger.Infof("Got login request with %v", req)
	if req.User == "" || req.OTP == "" || req.FP == "" {
		http.Error(w, "Missing user, otp or fp", http.StatusBadRequest)
		return
	}
	email := ""
	user := req.User
	// check if user is an email address
	if strings.Contains(user, "@") {
		// get the user id from the email
		email = req.User
		user, err = db.GetUserID(email)
		if err != nil || user == "" {
			http.Error(w, "Invalid Credentials", http.StatusUnauthorized)
			return
		}
	} else {
		// get the email from the user id
		email, err = db.GetEmail(req.User)
		if err != nil || email == "" {
			http.Error(w, "Invalid Credentials", http.StatusUnauthorized)
			return
		}
	}

	// validate otp based on user's secret
	s, err := db.getUserSecret(user)
	if err != nil {
		http.Error(w, "Failed to get user's OTP secret", http.StatusInternalServerError)
		Logger.Errorf("Failed to get user's OTP secret: %s", err)
		return
	}
	if s == "" {
		http.Error(w, "User has no OTP configured", http.StatusUnauthorized)
		return
	}
	if !totp.Validate(req.OTP, s) {
		http.Error(w, "Wrong One Time Password, please try again", http.StatusUnauthorized)
		return
	}
	// check if the peer exists
	exists, err := db.PeerExists(req.FP)
	if err != nil {
		http.Error(w, "Failed to check if peer exists", http.StatusInternalServerError)
		Logger.Errorf("Failed to check if peer exists: %s", err)
		return
	}
	if !exists {
		// create the peer
		peer := NewPeer(req.FP, req.Name, user, "terminal7")
		err = db.AddPeer(peer)
		if err != nil {
			http.Error(w, "Failed to add peer", http.StatusInternalServerError)
			Logger.Errorf("Failed to add peer: %s", err)
			return
		}
	} else {
		err = db.RenamePeer(req.FP, req.Name)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to rename peer: %s", err), http.StatusInternalServerError)
			return
		}
		err = db.SetPeerUser(req.FP, user)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to set peer: %s", err), http.StatusUnauthorized)
			return
		}
	}
	err = sendVerifyEmail(email, req.FP)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to send email: %s", err), http.StatusInternalServerError)
		return
	}

	// retrun a status code of 201
	http.Error(w, fmt.Sprintf("Email sent to %s", email), http.StatusCreated)

}
func sendVerifyEmail(email string, fp string) error {
	if !db.canSendEmail(email) {
		return fmt.Errorf("Throttling prevented sending email to %q", email)
	}
	Logger.Infof("Sending verification email to: %s for %s", email, fp)
	m := gomail.NewMessage()
	clickL, err := createTempURL(fp, "verify", false)
	if err != nil {
		return fmt.Errorf("Failed to create temp URL: %s", err)
	}
	htmlT, err := template.ParseFS(tFS, "templates/verify_client_email.html.tmpl")
	if err != nil {
		return fmt.Errorf("Failed to parse the html template: %s", err)
	}
	plainT, err := template.ParseFS(tFS, "templates/verify_client_email.plain.tmpl")
	if err != nil {
		return fmt.Errorf("Failed to parse the plain template: %s", err)
	}
	context := struct {
		URL     string
		HomeURL string
	}{URL: clickL, HomeURL: os.Getenv("PB_HOME_URL")}
	var p bytes.Buffer
	err = plainT.Execute(&p, context)
	if err != nil {
		return fmt.Errorf("Failed to execute template: %s", err)
	}
	m.SetBody("text/plain", p.String(), gomail.SetPartEncoding(gomail.Unencoded))
	var h bytes.Buffer
	err = htmlT.Execute(&h, context)
	if err != nil {
		return fmt.Errorf("Failed to execute template: %s", err)
	}
	m.AddAlternative("text/html", h.String(), gomail.SetPartEncoding(gomail.Unencoded))

	m.SetHeaders(map[string][]string{
		"From":               {m.FormatAddress("support@tuzig.com", "PeerBook Support")},
		"To":                 {email},
		"Subject":            {"A peer is waiting your approval"},
		"X-SES-MESSAGE-TAGS": {"genre=auth_email"},
	})
	err = sendEmail(m)
	if err != nil {
		return fmt.Errorf("Failed to send email: %s", err)
	}
	Logger.Infof("Email sent to %s", email)
	return nil
}
func sendEmail(m *gomail.Message) error {
	host := os.Getenv("PB_SMTP_HOST")
	port := os.Getenv("PB_SMTP_PORT")
	if port == "" {
		port = "587"
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("Failed to convert port to int: %s", err)
	}
	user := os.Getenv("PB_SMTP_USER")
	pass := os.Getenv("PB_SMTP_PASS")
	d := gomail.NewPlainDialer(host, portInt, user, pass)

	// Display an error message if something goes wrong; otherwise,
	// display a message confirming that the message was sent.
	if err := d.DialAndSend(m); err != nil {
		Logger.Errorf("Failed to send email: %s", err)
	}
	return nil
}

func serveAuthPage(w http.ResponseWriter, r *http.Request) {
	user, err := getStrFromEncodedPath(r)
	if err != nil {
		goHome(w, r, "Stale token, please try again")
		Logger.Warnf("Failed to get user from req: %s", err)
		return
	}
	peers, err := GetUsersPeers(user)
	if err != nil {
		msg := fmt.Sprintf("Failed to get user peers: %s", err)
		Logger.Error(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	if peers == nil {
		peers = &PeerList{}
	}
	var data ListContext
	if peers == nil {
		data.Peers = &PeerList{}
	} else {
		data.Peers = peers
	}
	email, err := db.GetEmail(user)
	if err != nil {
		msg := fmt.Sprintf("Failed to get user email: %s", err)
		Logger.Error(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	data.User = email
	verified := db.IsQRVerified(user)
	if !verified {
		// show the QR code
		a, err := createTempURL(user, "qr", true)
		if err != nil {
			msg := fmt.Sprintf("Got an error creating temp url: %s", err)
			Logger.Warnf(msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, a, http.StatusSeeOther)
		return
	}
	if r.Method == "POST" {
		var otp string
		err := r.ParseForm()
		if err != nil {
			msg := fmt.Sprintf("Got an error parsing form: %s", err)
			Logger.Warnf(msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		btn := r.FormValue("btn")
		if btn == "update" {
			otp = r.FormValue("otp")
		} else {
			otp = r.FormValue("deleteOTP")
		}
		Logger.Debugf("Got button %v %s otp %s", r.Form["btn"], btn, otp)
		// validate otp based on user's secret
		s, err := db.getUserSecret(user)
		if err != nil {
			msg := fmt.Sprintf("Failed to get user's OTP secret: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
			Logger.Errorf(msg)
			return
		}
		if s == "" {
			http.Error(w, `{"m": "User has no OTP configured"}`, http.StatusUnauthorized)
			return
		}
		if !totp.Validate(otp, s) {
			data.Message = "Wrong One Time Password, please try again"
		} else {
			switch btn {
			case "update":
				data = handleUpdate(r, user, peers)
			case "delete":
				data = handleDelete(r.FormValue("deleteOption"), user, peers)
				goto render
			default:
				data.Message = "Bad button"
			}
		}
	} else if r.Method == "GET" {
		data.Message = r.URL.Query().Get("m")
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
render:
	if !data.Clean {
		tmpl, err := template.ParseFS(tFS, "templates/pb.tmpl", "templates/base.tmpl")
		if err != nil {
			msg := fmt.Sprintf("Failed to parse the template: %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		err = tmpl.Execute(w, data)
		if err != nil {
			Logger.Warnf("Failed to execute the main template: %s", err)
		}
		return
	}
	goHome(w, r, data.Message)
}

func handleUpdate(r *http.Request, user string, peers *PeerList) ListContext {
	// fill the context with all the peers
	var ret ListContext
	verified := make(map[string]bool)
	for k, _ := range r.Form {
		if k == "otp" || k == "rmrf" {
			continue
		}
		Logger.Infof("Got key %s", k)
		// if key start with "del-" remove the peer
		if strings.HasPrefix(k, "del-") {
			fp := k[4:]
			Logger.Infof("Deleting peer %s\n", fp)
			err := db.DeletePeer(fp)
			if err != nil {
				msg := fmt.Sprintf("Failed to delete peer: %s", err)
				ret.Message = msg
				return ret
			}
			// remove the peer from the list
			for i, p := range *peers {
				if p.FP == fp {
					*peers = append((*peers)[:i], (*peers)[i+1:]...)
					break
				}
			}
			continue
		}
		verified[k] = true
	}
	for _, p := range *peers {
		var err error
		_, toBeV := verified[p.FP]
		if p.Verified && !toBeV {
			p.Verified = false
			err = VerifyPeer(p.FP, false)
		}
		if !p.Verified && toBeV {
			p.Verified = true
			err = VerifyPeer(p.FP, true)
		}
		if err != nil {
			msg := fmt.Sprintf("Failed to verify peer: %s", err)
			Logger.Errorf(msg)
			ret.Message = msg
			return ret
		}
	}
	ret.Message = "Your PeerBook was updated"
	ret.Peers = peers
	return ret
}

func handleDelete(option string, user string, peers *PeerList) ListContext {
	ret := ListContext{Peers: &PeerList{}}
	switch option {
	case "rmPeers":
		Logger.Infof("Removing user %s and his peers", user)
		conn := db.pool.Get()
		for _, p := range *peers {
			conn.Do("DEL", p.Key())
		}
		key := fmt.Sprintf("userset:%s", user)
		conn.Do("DEL", key)
		conn.Close()
		ret.Message = "Your peers were removed"
	case "rmUser":
		Logger.Infof("Removing user %s", user)
		err := db.RemoveUser(user, *peers)
		if err != nil {
			msg := fmt.Sprintf("Failed to remove user: %s", err)
			Logger.Errorf(msg)
			ret.Message = msg
		} else {
			ret.Message = "All your data was removed"
			ret.Clean = true
		}
	default:
		ret.Message = "Bad delete option: " + option
	}
	return ret
}
func serveHitMe(w http.ResponseWriter, r *http.Request) {
	var data struct {
		Message string
		User    string
	}
	var uid string
	var email string
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			msg := fmt.Sprintf("Got an error parsing form: %s", err)
			Logger.Warnf(msg)
			data.Message = msg
			goto render
		}
		email = r.Form.Get("email")
		if email == "" {
			data.Message = "Failed as no email was posted"
			goto render
		}
		uid, err = db.GetUserID(email)
		if err != nil {
			data.Message = fmt.Sprintf("Failed to get user ID: %s", err)
			goto render
		}
		err = sendAuthEmail(email, uid)
		if err != nil {
			data.Message = fmt.Sprintf("Failed to send email: %s", err)
			goto render
		}
		data.Message = "You've been hit with the email stick"
		data.User = email
	render:
		tmpl, err := template.ParseFS(tFS, "templates/index.tmpl", "templates/base.tmpl")
		if err != nil {
			msg := fmt.Sprintf("Failed to parse the template: %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		err = tmpl.Execute(w, data)
		if err != nil {
			msg := fmt.Sprintf("Failed to execute the main template: %s", err)
			Logger.Error(msg)
			http.Error(w, msg, http.StatusInternalServerError)
		}
	}
}
func serveVerifyPeer(w http.ResponseWriter, r *http.Request) {
	fp, err := getStrFromEncodedPath(r)
	if err != nil {
		http.Error(w, "Stale token, please try again", http.StatusUnauthorized)
		Logger.Warnf("Failed to get user from req: %s", err)
		return
	}
	if r.Method == "GET" {
		tmpl, err := template.New("verify_peer.tmpl").Funcs(template.FuncMap{"date": FormatDateInt}).ParseFS(tFS, "templates/verify_peer.tmpl", "templates/base.tmpl")
		if err != nil {
			msg := fmt.Sprintf("Failed to parse the template: %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		peer, err := GetPeer(fp)
		if err != nil {
			msg := fmt.Sprintf("Failed to get peer: %s", err)
			Logger.Errorf(msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		var data struct {
			Peer    *Peer
			Message string
			User    string
		}
		data.Peer = peer
		data.Message = r.URL.Query().Get("m")
		err = tmpl.Execute(w, data)
		if err != nil {
			msg := fmt.Sprintf("Failed to execute the main template: %s", err)
			Logger.Error(msg)
			http.Error(w, msg, http.StatusInternalServerError)
		}
		return
	}
	Logger.Infof("Handling request to verify peer %s", fp)
	err = VerifyPeer(fp, true)
	if err != nil {
		msg := fmt.Sprintf("Failed to verify peer: %s", err)
		Logger.Errorf(msg)
		http.Error(w, msg, http.StatusInternalServerError)
	}
	// Send the peer list to the client
	Logger.Infof("Peer %s verified", fp)
	user, err := db.GetUID4FP(fp)
	if err != nil {
		msg := fmt.Sprintf("Failed to get user ID: %s", err)
		Logger.Errorf(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	m, err := GetPeersMessage(user)
	if err != nil {
		msg := fmt.Sprintf("Failed to get peers: %s", err)
		Logger.Errorf(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	err = SendMessage(fp, m)
	if err != nil {
		msg := fmt.Sprintf("Failed to send message: %s", err)
		Logger.Errorf(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	a, err := createTempURL(user, "pb", true)
	if err != nil {
		msg := fmt.Sprintf("Failed to create temp url: %s", err)
		Logger.Errorf(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	a = fmt.Sprintf("%s?m=%s", a, url.PathEscape("Peer verified"))
	http.Redirect(w, r, a, http.StatusSeeOther)
	return
}

// serveVerify is the handler for the /verify endpoint
// It is used to verify and create a peer.
// If succesfull returns 201 for newly created peers or 200 for already
// existing peers and a JSON object with `uid` & `verfified` for
// the peer's user id and whether it's verified.
func serveVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req map[string]string
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&req)
	if err != nil {
		http.Error(w, "Bad JSON", http.StatusBadRequest)
		return
	}
	fp := req["fp"]
	if fp == "" {
		http.Error(w, "Missing fingerprint", http.StatusBadRequest)
		return
	}
	uid := req["uid"]
	var peer *Peer
	pexists, err := db.PeerExists(fp)
	if err != nil {
		http.Error(w, "DB read failure", http.StatusInternalServerError)
		return
	}
	if !pexists {
		peer = NewPeer(fp, req["name"], uid, req["kind"])
		err = db.AddPeer(peer)
		if err != nil {
			msg := fmt.Sprintf("Failed to add peer: %s", err)
			Logger.Warn(msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	} else {
		peer, err = GetPeer(fp)
		if err != nil {
			// turn err to a string
			msg := fmt.Sprintf("%s", err)
			Logger.Errorf(msg)
			m, _ := json.Marshal(map[string]string{"m": msg})
			http.Error(w, string(m), http.StatusInternalServerError)
			return
		}
		if peer.User != "" && uid != "" && peer.User != uid {
			msg := fmt.Sprintf(
				"Fingerprint is associated to another user: %s", peer.User)
			http.Error(w, msg, http.StatusConflict)
			return
		}
		if peer.Name != req["name"] {
			peer.setName(req["name"])
		}
	}
	var m []byte
	m, err = json.Marshal(map[string]interface{}{
		"verified": peer.Verified,
		"uid":      peer.User})

	if err != nil {
		msg := fmt.Sprintf("Failed to marshal user's list: %s", err)
		Logger.Errorf(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(m)
}
func serveHome(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path != "/" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tmpl, err := template.ParseFS(tFS, "templates/index.tmpl", "templates/base.tmpl")
	if err != nil {
		msg := fmt.Sprintf("Failed to parse the template: %s", err)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	var data struct {
		Message string
		User    string
	}
	data.Message = r.URL.Query().Get("m")
	err = tmpl.Execute(w, data)
	if err != nil {
		msg := fmt.Sprintf("Failed to execute template: %s", err)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
}

func initLogger() {
	zapConf := []byte(`{
		  "level": "debug",
		  "encoding": "console",
		  "outputPaths": ["stdout"],
		  "errorOutputPaths": ["stderr"],
		  "encoderConfig": {
		    "messageKey": "message",
		    "levelKey": "level",
		    "levelEncoder": "lowercase"
		  }
		}`)

	var cfg zap.Config
	if err := json.Unmarshal(zapConf, &cfg); err != nil {
		panic(err)
	}
	l, err := cfg.Build()
	Logger = l.Sugar()
	if err != nil {
		panic(err)
	}
	defer Logger.Sync()
}

// getCertificate returns a WebRTC certificate based on ED25519.
func generateCertificate() (*webrtc.Certificate, error) {
	secretKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate key: %w", err)
	}
	origin := make([]byte, 16)
	/* #nosec */
	if _, err := rand.Read(origin); err != nil {
		return nil, err
	}

	// Max random value, a 130-bits integer, i.e 2^130 - 1
	maxBigInt := new(big.Int)
	/* #nosec */
	maxBigInt.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(maxBigInt, big.NewInt(1))
	/* #nosec */
	serialNumber, err := rand.Int(rand.Reader, maxBigInt)
	if err != nil {
		return nil, err
	}

	return webrtc.NewCertificate(secretKey, x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		// NotAfter:              time.Now().AddDate(10, 0, 0),
		SerialNumber: serialNumber,
		Version:      2,
		Subject:      pkix.Name{CommonName: hex.EncodeToString(origin)},
		IsCA:         true,
	})
}

func startHTTPServer(addr string, wg *sync.WaitGroup) *http.Server {

	auth := NewUsersAuth()
	certificate, err := generateCertificate()
	if err != nil {
		Logger.Fatalf("Failed to generate certificate: %s", err)
		return nil
	}
	webrtcSetting := &webrtc.SettingEngine{}
	publicIP := os.Getenv("WEBRTC_IP_ADDRESS")
	if publicIP != "" {
		webrtcSetting.SetNAT1To1IPs([]string{publicIP}, webrtc.ICECandidateTypeHost)
	} else {
		Logger.Warn("WEBRTC_IP_ADDRESS is not set, WebRTC connections could fail")
	}

	peerConf := &peers.Conf{
		Certificate:       certificate,
		Logger:            Logger,
		DisconnectTimeout: 3 * time.Second,
		FailedTimeout:     3 * time.Second,
		KeepAliveInterval: 3 * time.Second,
		GatheringTimeout:  3 * time.Second,
		PortMin:           60000,
		PortMax:           61000,
		GetICEServers:     GetICEServers,
		// TODO: make the next two functions methods of connection
		OnCTRLMsg:     OnPeerMsg,
		OnStateChange: OnConnectionStateChange,
		WebrtcSetting: webrtcSetting,
	}
	webexecHandler := httpserver.NewConnectHandler(auth, peerConf, Logger)

	srv := &http.Server{
		Addr:    addr,
		Handler: webexecHandler.GetHandler(),
	}
	http.HandleFunc("/", serveHome)
	http.HandleFunc("/pb/", serveAuthPage)
	http.HandleFunc("/verify", serveVerify)
	http.HandleFunc("/verify/", serveVerifyPeer)
	http.HandleFunc("/hitme", serveHitMe)
	http.HandleFunc("/authorize/", serveAuthorize)
	http.HandleFunc("/ws", serveWs)
	// `/turn` is deprecated
	http.HandleFunc("/turn", serveICEServers)
	http.HandleFunc("/iceservers", serveICEServers)
	http.HandleFunc("/qr/", serveQR)
	http.HandleFunc("/rcwh", serveRCWH)
	http.HandleFunc("/we", webexecHandler.HandleConnect)
	http.HandleFunc("/offer", webexecHandler.HandleOffer)
	http.HandleFunc("/candidates/", webexecHandler.HandleCandidate)
	http.HandleFunc("/login", serveLogin)

	go func() {
		defer wg.Done() // let main know we are done cleaning up
		// always returns error. ErrServerClosed on graceful close
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			// unexpected error. port in use?
			Logger.Errorf("ListenAndServe failed: %v", err)
		} else {
			Logger.Infof("Listening for HTTP connection at %s", addr)
		}
	}()

	// returning reference so caller can call Shutdown()
	return srv
}

func createTempURL(uid string, prefix string, rel bool) (string, error) {
	var s string
	token, err := db.CreateToken(uid)
	if err != nil {
		return "", fmt.Errorf("Failed to create token: %w", err)
	}
	if !rel {
		s = os.Getenv("PB_HOME_URL")
		if s == "" {
			s = DefaultHomeURL
		}
	}
	parts := []string{s, prefix, url.PathEscape(token)}
	return strings.Join(parts, "/"), nil
}

// sendAuthEmail creates a short lived token and emails a message with a link
// to `/auth/<token>` so the javascript at /auth can read the list of peers and
// use checkboxes to enable/disable
func sendAuthEmail(email string, uid string) error {
	if !db.canSendEmail(email) {
		return fmt.Errorf("Throttling prevented sending email to %q", email)
	}
	Logger.Infof("Sending email to: %s, %s", email, uid)
	m := gomail.NewMessage()
	clickL, err := createTempURL(uid, "pb", false)
	if err != nil {
		return fmt.Errorf("Failed to create temp URL: %s", err)
	}
	htmlT, err := template.ParseFS(tFS, "templates/email.html.tmpl")
	if err != nil {
		return fmt.Errorf("Failed to parse the html template: %s", err)
	}
	plainT, err := template.ParseFS(tFS, "templates/email.plain.tmpl")
	if err != nil {
		return fmt.Errorf("Failed to parse the plain template: %s", err)
	}
	var p bytes.Buffer
	err = plainT.Execute(&p, clickL)
	if err != nil {
		return fmt.Errorf("Failed to execute template: %s", err)
	}
	m.SetBody("text/plain", p.String(), gomail.SetPartEncoding(gomail.Unencoded))
	var h bytes.Buffer
	err = htmlT.Execute(&h, clickL)
	if err != nil {
		return fmt.Errorf("Failed to execute template: %s", err)
	}
	m.AddAlternative("text/html", h.String(), gomail.SetPartEncoding(gomail.Unencoded))

	m.SetHeaders(map[string][]string{
		"From":               {m.FormatAddress("support@tuzig.com", "PeerBook Support")},
		"To":                 {email},
		"Subject":            {"A peer is waiting your approval"},
		"X-SES-MESSAGE-TAGS": {"genre=auth_email"},
	})

	err = sendEmail(m)
	if err != nil {
		return fmt.Errorf("Failed to send email: %s", err)
	}
	Logger.Infof("Email sent to %s", email)
	return nil
}
func getUserKey(user string) (*otp.Key, error) {
	s, err := db.getUserSecret(user)
	if err != nil {
		return nil, err
	}
	email, err := db.GetEmail(user)
	if err != nil {
		return nil, fmt.Errorf("Failed to get email for %q: %w", user, err)
	}
	u := fmt.Sprintf("otpauth://totp/PeerBook:%s?algorithm=SHA1&digits=6&secret=%s&issuer=PeerBook&period=30", email, s)
	return otp.NewKeyFromURL(u)

}
func goHome(w http.ResponseWriter, r *http.Request, msg string) {
	a := fmt.Sprintf("/?m=%s", url.PathEscape(msg))
	http.Redirect(w, r, a, http.StatusSeeOther)
	return
}
func serveQR(w http.ResponseWriter, r *http.Request) {
	var msg string

	user, err := getStrFromEncodedPath(r)
	if err != nil {
		goHome(w, r, "Stale token, please try again")
		Logger.Warnf("Failed to get user from req: %s", err)
		return
	}
	if db.IsQRVerified(user) {
		/* TODO: make it nicer */
		goHome(w, r, `Your QR was already scanned and verified.
If you lost your device please use the account-recovery channel on our discord server`)
		return
	}
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			msg = fmt.Sprintf("Bad Form: %s", err)
			goto render
		}
		s, err := db.getUserSecret(user)
		if err != nil {
			msg = fmt.Sprintf("Failed to get user's secret: %s", err)
			goto render
		}
		otp := r.Form.Get("otp")
		if !totp.Validate(otp, s) {
			msg = "One Time Password validation failed, please try again"
			goto render
		}
		a, err := createTempURL(user, "pb", true)
		if err != nil {
			msg = fmt.Sprintf("Failed to create temp url: %s", err)
			goto render
		}
		a = fmt.Sprintf("%s?m=%s", a, url.PathEscape("One Time Password verified"))
		err = db.SetQRVerified(user)
		if err != nil {
			msg = fmt.Sprintf("failed to save QRVerified: %s", err)
			goto render
		}
		http.Redirect(w, r, a, http.StatusSeeOther)
		return
	} else if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
render:
	// getting the qr and rendering the html page
	img, err := GetQRImage(user)
	if err != nil {
		msg := fmt.Sprintf("Failed to get QR image: %s", err)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFS(tFS, "templates/qr.tmpl",
		"templates/base.tmpl")
	if err != nil {
		msg := fmt.Sprintf("Failed to parse the template: %s", err)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	// and return the html
	var d struct {
		Message string
		User    string
		Image   string
		Token   string
	}
	d.Image = img
	d.User = user
	d.Message = msg
	// create a new URL to reset the timer
	token, err := db.CreateToken(user)
	if err != nil {
		d.Message = fmt.Sprintf("Failed to create temp url: %s", err)
	} else {
		d.Token = token
	}
	err = tmpl.Execute(w, d)
	if err != nil {
		msg := fmt.Sprintf("Failed to execute the QR template: %s", err)
		Logger.Error(msg)
		http.Error(w, msg, http.StatusInternalServerError)
	}
}

func main() {
	addr := flag.String(
		"addr", "0.0.0.0:17777", "address to listen for http requests")
	redisH := os.Getenv("REDIS_HOST")
	if redisH == "" {
		redisH = "127.0.0.1:6379"
	}
	flag.Parse()
	if Logger == nil {
		initLogger()
	}
	err := db.Connect(redisH)
	if err != nil {
		Logger.Errorf("Failed to connect to redis: %s", err)
		os.Exit(1)
	}
	Logger.Infof("Using redis server at: %s", redisH)
	if len(os.Args) == 2 {
		if os.Args[1] == "reset" {
			db.Reset()
			return
		} else {
			Logger.Errorf("Unknown argument: %s", os.Args[1])
			os.Exit(1)
		}
	}

	hub = Hub{
		register:   make(chan *Conn),
		unregister: make(chan *Conn),
		requests:   make(chan map[string]interface{}, 16),
	}
	Logger.Infof("Starting peerbook")
	go hub.run()

	httpServerExitDone := &sync.WaitGroup{}
	httpServerExitDone.Add(1)
	srv := startHTTPServer(*addr, httpServerExitDone)
	// Setting up signal capturing
	stop = make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	connections.StopAll()
	if err = srv.Shutdown(context.Background()); err != nil {
		Logger.Error("failure/timeout shutting down the http server gracefully")
	}
	// wait for goroutine started in startHTTPServer() to stop
	httpServerExitDone.Wait()
}
