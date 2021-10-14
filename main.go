// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"image/png"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/gomodule/redigo/redis"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rs/cors"
	"go.uber.org/zap"
	"gopkg.in/gomail.v2" //go get gopkg.in/gomail.v2
)

const (
	// SendChanSize is the size of the send channel in messages
	SendChanSize = 4
	HTMLThankYou = `<html lang=en> <head><meta charset=utf-8>
<title>Thank You</title>
</head>
<body><h2>Your changes have been recorded<h2>
<h3>Please ensure your servers and started and clients refreshed</h3>`

	HTMLPostrmrf = `<html lang=en> <head><meta charset=utf-8>
<title>Thank You</title>
</head>
<body><h2>All your peers and your email were deleted</h2>`

	HTMLEmailSent = `<html lang=en> <head><meta charset=utf-8>
<title>Peerbook</title>
</head>
<body><h2>Please check your inbox for your peerbook link</h2>

`
	DefaultHomeUrl = "https://pb.terminal7.dev"
)

// Logger is our global logger
var (
	Logger *zap.SugaredLogger
	stop   chan os.Signal
	db     DBType
	hub    Hub
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

// NoSecret is an error
type NewSecret struct{}

func (e *NewSecret) Error() string {
	return "Couldn't find a secret, generated a new one"
}

func serveAuthPage(w http.ResponseWriter, r *http.Request) {
	i := strings.IndexRune(r.URL.Path[1:], '/')
	t := r.URL.Path[i+2:]
	token, err := url.PathUnescape(t)
	if err != nil {
		Logger.Warnf(
			"Failed to unescape token: err: %s, token: %s", err, token)
		http.Error(w, "Bad Token", http.StatusBadRequest)
		return
	}

	user, err := db.GetToken(token)
	if err != nil || user == "" {
		Logger.Warnf("Failed to get token: err: %s, token: %s", err, token)
		http.Error(w, "Bad Token", http.StatusBadRequest)
		return
	}
	peers, err := GetUsersPeers(user)
	if err != nil {
		msg := fmt.Sprintf("Failed to get user peers: %s", err)
		Logger.Error(msg)
		http.Error(w, msg, http.StatusInternalServerError)
	}
	var data struct {
		Message string
		User    string
		Peers   *PeerList
	}
	data.Peers = peers
	data.User = user
	verified := db.IsQRVerified(user)
	if !verified {
		serveQRCode(w, user)
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
		s, err := getUserSecret(user)
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
				defer conn.Close()
				for _, p := range *peers {
					conn.Do("DEL", p.Key())
				}
				key := fmt.Sprintf("user:%s", user)
				conn.Do("DEL", key)
				w.Write([]byte(HTMLPostrmrf))
				return
			}
			verified := make(map[string]bool)
			for k, _ := range r.Form {
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
	} else if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	base := fmt.Sprintf("%s/base.tmpl", os.Getenv("PB_STATIC_ROOT"))
	main := fmt.Sprintf("%s/main.tmpl", os.Getenv("PB_STATIC_ROOT"))
	tmpl, err := template.ParseFiles(main, base)
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
func serveHitMe(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			msg := fmt.Sprintf("Got an error parsing form: %s", err)
			Logger.Warnf(msg)
			http.Error(w, `{"msg": "`+msg+`"}`, http.StatusBadRequest)
			return
		}
		email := r.Form.Get("email")
		if email == "" {
			msg := "Got a hitme request with no email"
			Logger.Warnf(msg)
			http.Error(w, `{"msg": "`+msg+`"}`, http.StatusBadRequest)
			return
		}
		sendAuthEmail(email)
		w.Write([]byte(HTMLEmailSent))
	}
}
func serveVerify(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&req)
	fp := req["fp"]
	email := req["email"]
	if err != nil {
		http.Error(w, "Bad JSON", http.StatusBadRequest)
		return
	}
	if fp == "" {
		http.Error(w, "Missing fingerprint", http.StatusBadRequest)
		return
	}
	if email == "" {
		http.Error(w, "Missing email", http.StatusBadRequest)
		return
	}
	if r.Method == "POST" {
		var peer *Peer
		pexists, err := db.PeerExists(fp)
		if err != nil {
			http.Error(w, "DB read failure", http.StatusInternalServerError)
			return
		}
		if !pexists {
			peer = NewPeer(fp, req["name"], email, req["kind"])
			err = db.AddPeer(peer)
			if err != nil {
				msg := fmt.Sprintf("Failed to add peer: %s", err)
				Logger.Warn(msg)
				http.Error(w, msg, http.StatusInternalServerError)
				return
			}
			sendAuthEmail(email)
		} else {
			peer, err = GetPeer(fp)
			if err != nil {
				msg := fmt.Sprintf("Failed to get peer: %s", err)
				Logger.Errorf(msg)
				m, _ := json.Marshal(map[string]string{"m": msg})
				http.Error(w, string(m), http.StatusInternalServerError)
				return
			}
			if peer.User == "" {
				peer = NewPeer(fp, req["name"], email, req["kind"])
				err = db.AddPeer(peer)
				if err != nil {
					msg := fmt.Sprintf("Failed to add peer: %s", err)
					Logger.Warn(msg)
					http.Error(w, msg, http.StatusInternalServerError)
					return
				}
			} else if peer.User != email {
				msg := fmt.Sprintf(
					"Fingerprint is associated to another email: %s", peer.User)
				http.Error(w, msg, http.StatusConflict)
				return
			}
			if peer.Name != req["name"] {
				peer.setName(req["name"])
			}
			if !peer.Verified {
				sendAuthEmail(email)
			}
		}
		var m []byte
		if peer.Verified {
			ps, err := GetUsersPeers(peer.User)
			if err != nil {
				msg := fmt.Sprintf("Failed to get user peers: %s", err)
				Logger.Errorf(msg)
				http.Error(w, msg, http.StatusInternalServerError)
				return
			}
			m, err = json.Marshal(map[string]interface{}{"peers": ps})
			if err != nil {
				msg := fmt.Sprintf("Failed marshel peers: %s", err)
				Logger.Errorf(msg)
				http.Error(w, msg, http.StatusInternalServerError)
				return
			}
		} else {
			m, err = json.Marshal(map[string]bool{"verified": peer.Verified})
			if err != nil {
				msg := fmt.Sprintf("Failed to marshal user's list: %s", err)
				Logger.Errorf(msg)
				http.Error(w, msg, http.StatusInternalServerError)
				return
			}
		}
		w.Write(m)
	}
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
	p := fmt.Sprintf("%s/index.html", os.Getenv("PB_STATIC_ROOT"))
	http.ServeFile(w, r, p)
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

func startHTTPServer(addr string, wg *sync.WaitGroup) *http.Server {
	srv := &http.Server{
		Addr: addr, Handler: cors.Default().Handler(http.DefaultServeMux)}

	http.HandleFunc("/", serveHome)
	http.HandleFunc("/auth/", serveAuthPage)
	http.HandleFunc("/verify", serveVerify)
	http.HandleFunc("/hitme", serveHitMe)
	http.HandleFunc("/ws", serveWs)
	http.HandleFunc("/validate_otp", serveValidateOTP)

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

func createAuthURL(email string) (string, error) {
	// TODO: send an email in the background
	token, err := db.CreateToken(email)
	if err != nil {
		return "", fmt.Errorf("Failed to create token: %w", err)
	}
	homeUrl := os.Getenv("PB_HOME_URL")
	if homeUrl == "" {
		homeUrl = DefaultHomeUrl
	}
	return fmt.Sprintf("%s/auth/%s", homeUrl, url.PathEscape(token)), nil
}

// sendAuthEmail creates a short lived token and emails a message with a link
// to `/auth/<token>` so the javascript at /auth can read the list of peers and
// use checkboxes to enable/disable
func sendAuthEmail(email string) {
	err := initUser(email)
	if err != nil {
		Logger.Errorf("Failed to generate TOTP key: %s", err)
		return
	}
	if !db.canSendEmail(email) {
		Logger.Warnf("Throttling prevented sending email to %q", email)
		return
	}
	m := gomail.NewMessage()
	clickL, err := createAuthURL(email)
	if err != nil {
		Logger.Errorf("Failed to sendte temp URL: %s", err)
		return
	}
	m.SetBody("text/html", `<html lang=en> <head><meta charset=utf-8>
<title>Peerbook updates for your approval</title>
</head>
Please click <a href="`+clickL+`">here to review</a>.`)

	text := fmt.Sprintf("Please click to review:\n%s", clickL)
	m.AddAlternative("text/plain", text)

	m.SetHeaders(map[string][]string{
		"From":               {m.FormatAddress("support@tuzig.com", "Terminal7")},
		"To":                 {email},
		"Subject":            {"Pending changes to your peerbook"},
		"X-SES-MESSAGE-TAGS": {"genre=auth_email"},
		// Comment or remove the next line if you are not using a configuration set
		// "X-SES-CONFIGURATION-SET": {ConfigSet},
	})

	host := os.Getenv("PB_SMTP_HOST")
	user := os.Getenv("PB_SMTP_USER")
	pass := os.Getenv("PB_SMTP_PASS")
	d := gomail.NewPlainDialer(host, 587, user, pass)

	Logger.Infof("Sending email %q", text)
	// Display an error message if something goes wrong; otherwise,
	// display a message confirming that the message was sent.
	if err := d.DialAndSend(m); err != nil {
		Logger.Errorf("Failed to send email: %s", err)
	} else {
		Logger.Infof("Send email to %q", email)
	}
}

func getUserKey(user string) (*otp.Key, error) {
	s, err := getUserSecret(user)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("otpauth://totp/PeerBook:%s?algorithm=SHA1&digits=6&secret=%s&issuer=PeerBook&period=30", user, s)
	return otp.NewKeyFromURL(u)

}
func getUserSecret(user string) (string, error) {
	var secret string
	key := fmt.Sprintf("secret:%s", user)
	conn := db.pool.Get()
	defer conn.Close()
	secret, err := redis.String(conn.Do("GET", key))
	if err != nil {
		return "", err
	}
	return secret, nil
}

func initUser(user string) error {
	conn := db.pool.Get()
	defer conn.Close()
	key := fmt.Sprintf("secret:%s", user)
	exists, err := redis.Bool(conn.Do("EXISTS", key))
	if err != nil {
		return err
	}
	if !exists {
		ok, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "PeerBook",
			AccountName: user,
		})
		if err != nil {
			return fmt.Errorf("Failed to generate a TOTP key")
		}
		// all is well, save the secret
		secret := ok.Secret()
		key := fmt.Sprintf("secret:%s", user)
		_, err = conn.Do("SET", key, secret)
		if err != nil {
			return fmt.Errorf("Failed to save the user's secret")
		}
	}
	return nil
}

func serveQRCode(w http.ResponseWriter, user string) {
	var qr bytes.Buffer

	if db.IsQRVerified(user) {
		/* TODO: make it nicer */
		http.Error(w, `Your QR was already scanned and verified.
If you lost your device please contact the account-recovery channel on our community server`,
			http.StatusNotImplemented)
		return
	}
	ok, err := getUserKey(user)
	if err != nil {
		msg := fmt.Sprintf("Failed to get users secret key QR iomage: %S", err)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	img, err := ok.Image(200, 200)
	if err != nil {
		msg := fmt.Sprintf("Failed to get the QR image: %S", err)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	encoder := base64.NewEncoder(base64.StdEncoding, &qr)
	png.Encode(encoder, img)
	encoder.Close()
	p := fmt.Sprintf("%s/verifyQR.html", os.Getenv("PB_STATIC_ROOT"))
	tmpl, err := template.ParseFiles(p)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse the template: %s", err)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	// and return the html
	var d struct {
		Image string
		Token string
	}
	d.Image = qr.String()
	// create a new URL to reset the timer
	token, err := db.CreateToken(user)
	if err != nil {
		http.Error(w, "Failed to create temp url",
			http.StatusInternalServerError)
		return
	}
	d.Token = token
	err = tmpl.Execute(w, d)
	if err != nil {
		msg := fmt.Sprintf("Failed to execute the verifyQR template: %s", err)
		Logger.Error(msg)
		http.Error(w, msg, http.StatusInternalServerError)
	}
}

func serveValidateOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Bad Form", http.StatusBadRequest)
		return
	}
	Logger.Info("validating OTP. form: %v", r.Form)
	token := r.Form.Get("token")
	if token == "" {
		http.Error(w, "Request must have a token", http.StatusBadRequest)
		return
	}
	user, err := db.GetToken(token)
	if err != nil {
		msg := fmt.Sprintf("Failed to read : %s", err)
		http.Error(w, msg, http.StatusInternalServerError)
		Logger.Warn(msg)
		return
	}
	s, err := getUserSecret(user)
	if err != nil {
		msg := fmt.Sprintf("Failed to get user's secret: %s", err)
		http.Error(w, msg, http.StatusInternalServerError)
		Logger.Warn(msg)
		return
	}
	otp := r.Form.Get("otp")
	if !totp.Validate(otp, s) {
		http.Error(w, "Wrong one time password, please go back and try again",
			http.StatusUnauthorized)
		Logger.Infof("OTP validation failed otp: %s s: %s", otp, s)
		return
	}
	a, err := createAuthURL(user)
	if err != nil {
		http.Error(w, "Failed to create temp url",
			http.StatusInternalServerError)
		return
	}
	err = db.SetQRVerified(user)
	if err != nil {
		Logger.Errorf("failed to save QRVerified: %s", err)
		return
	}
	http.Redirect(w, r, a, http.StatusSeeOther)
}

func main() {
	addr := flag.String("addr", "0.0.0.0:17777", "address to listen for http requests")
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
