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
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v3"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rs/cors"
	"github.com/tuzig/webexec/httpserver"
	"github.com/tuzig/webexec/peers"
	"go.uber.org/zap"
	"gopkg.in/gomail.v2" //go get gopkg.in/gomail.v2
)

const (
	// SendChanSize is the size of the send channel in messages
	SendChanSize = 4

	// TODO: remove the api
	DefaultHomeURL = "https://peerbook.io"
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

func (p *PeerChanged) Error() string {
	return "Peer exists with different properties"
}

// getUIDFromRequest It works assuming a valid token is the second
// url part
func getUIDFromRequest(r *http.Request) (string, error) {
	i := strings.IndexRune(r.URL.Path[1:], '/')
	t := r.URL.Path[i+2:]
	token, err := url.PathUnescape(t)
	if err != nil {
		return " ", fmt.Errorf("Failed to unescape token: err: %w", err)
	}

	user, err := db.GetToken(token)
	if err != nil || user == "" {
		return " ", fmt.Errorf("Failed to get token: err: %w", err)
	}
	return user, nil
}

func serveAuthPage(w http.ResponseWriter, r *http.Request) {
	user, err := getUIDFromRequest(r)
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
	var data struct {
		Message string
		User    string
		Peers   *PeerList
	}
	if peers == nil {
		data.Peers = &PeerList{}
	} else {
		data.Peers = peers
	}
	data.User = user
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
		err := r.ParseForm()
		if err != nil {
			msg := fmt.Sprintf("Got an error parsing form: %s", err)
			Logger.Warnf(msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		otp := r.Form.Get("otp")
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
			_, rmrf := r.Form["rmrf"]
			if rmrf {
				Logger.Infof("Removing user %s and his peers", user)
				conn := db.pool.Get()
				for _, p := range *peers {
					conn.Do("DEL", p.Key())
				}
				key := fmt.Sprintf("user:%s", user)
				conn.Do("DEL", key)
				conn.Close()
				data.Peers = nil
				data.Message = "Your peers were removed"
				goto render
			}
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
						Logger.Errorf(msg)
						http.Error(w, msg, http.StatusInternalServerError)
						return
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
					http.Error(w, msg, http.StatusInternalServerError)
					return
				}
			}
			data.Message = "Your PeerBook was updated"
		}
	} else if r.Method == "GET" {
		data.Message = r.URL.Query().Get("m")
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
render:
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
			msg := fmt.Sprintf("Failed to get peer: %s", err)
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
	srv := &http.Server{
		Addr: addr, Handler: cors.Default().Handler(http.DefaultServeMux)}

	auth := NewUsersAuth()
	certificate, err := generateCertificate()
	if err != nil {
		Logger.Fatalf("Failed to generate certificate: %s", err)
		return nil
	}
	peerConf := &peers.Conf{
		Certificate:       certificate,
		Logger:            Logger,
		DisconnectTimeout: 3 * time.Second,
		FailedTimeout:     3 * time.Second,
		KeepAliveInterval: 3 * time.Second,
		GatheringTimeout:  3 * time.Second,
		RunCommand:        RunCommand,
		PortMin:           60000,
		PortMax:           61000,
		GetICEServers:     GetICEServers,
	}
	webexecHandler := httpserver.NewConnectHandler(auth, peerConf, Logger)
	http.HandleFunc("/", serveHome)
	http.HandleFunc("/pb/", serveAuthPage)
	http.HandleFunc("/verify", serveVerify)
	http.HandleFunc("/hitme", serveHitMe)
	http.HandleFunc("/authorize/", serveAuthorize)
	http.HandleFunc("/ws", serveWs)
	// `/turn` is deprecated
	http.HandleFunc("/turn", serveICEServers)
	http.HandleFunc("/iceservers", serveICEServers)
	http.HandleFunc("/qr/", serveQR)
	http.HandleFunc("/rcwh", serveRCWH)
	http.HandleFunc("/we", webexecHandler.HandleConnect)

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
	m.SetBody("text/plain", p.String())
	var h bytes.Buffer
	err = htmlT.Execute(&h, clickL)
	if err != nil {
		return fmt.Errorf("Failed to execute template: %s", err)
	}
	m.AddAlternative("text/html", h.String())

	m.SetHeaders(map[string][]string{
		"From":               {m.FormatAddress("support@tuzig.com", "PeerBook Support")},
		"To":                 {email},
		"Subject":            {"A peer is waiting your approval"},
		"X-SES-MESSAGE-TAGS": {"genre=auth_email"},
	})

	host := os.Getenv("PB_SMTP_HOST")
	user := os.Getenv("PB_SMTP_USER")
	pass := os.Getenv("PB_SMTP_PASS")
	d := gomail.NewPlainDialer(host, 587, user, pass)

	// Display an error message if something goes wrong; otherwise,
	// display a message confirming that the message was sent.
	if err := d.DialAndSend(m); err != nil {
		Logger.Errorf("Failed to send email: %s", err)
	} else {
		Logger.Infof("Sent email to %q", email)
	}
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

	user, err := getUIDFromRequest(r)
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
	if err = srv.Shutdown(context.Background()); err != nil {
		Logger.Error("failure/timeout shutting down the http server gracefully")
	}
	// wait for goroutine started in startHTTPServer() to stop
	httpServerExitDone.Wait()
}
