// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/rs/cors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
)

const HTMLThankYou = `<html lang=en> <head><meta charset=utf-8>
<title>Thank You</title>
</head>
<body><h2>Your changes have been recorded and connected peers notified</h2>`

const HTMLEmailSent = `<html lang=en> <head><meta charset=utf-8>
<title>Peerbook</title>
</head>
<body><h2>Please check your inbox for your peerbook link</h2>

`

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
	peer *Peer
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

func serveList(w http.ResponseWriter, r *http.Request) {
	i := strings.IndexRune(r.URL.Path[1:], '/')
	user, err := db.GetToken(r.URL.Path[i+2:])
	if err != nil {
		http.Error(w, `{"m": "Bad Token"}`, http.StatusBadRequest)
		Logger.Errorf("Failed to get token: %s", err)
		return
	}
	if user == "" {
		http.Error(w, `{"m": "Bad Token"}`, http.StatusBadRequest)
		Logger.Warnf("Token not found, coauld be expired")
		return
	}
	peers, err := GetUsersPeers(user)
	if err != nil {
		http.Error(w, `{"m": "Failed to get user"}`, http.StatusBadRequest)
		Logger.Errorf("Failed to get user %q peers: %w", user, err)
		return
	}
	if r.Method == "GET" {
		m, err := json.Marshal(peers)
		if err != nil {
			Logger.Errorf("Failed to marshal user's list: %w", err)
			return
		}
		w.Write(m)
		return
	}
	if r.Method == "POST" {
		verified := make(map[string]bool)
		err := r.ParseForm()
		if err != nil {
			msg := fmt.Sprintf("Got an error parsing form: %s", err)
			Logger.Warnf(msg)
			http.Error(w, `{"msg": "`+msg+`"}`, http.StatusBadRequest)
			return
		}
		for k, _ := range r.Form {
			verified[k] = true
		}
		notify := false
		for _, p := range *peers {
			_, toBeV := verified[p.FP]
			peer := *p
			if peer.Verified && !toBeV {
				peer.Verify(false)
				notify = true
			}
			if !peer.Verified && toBeV {
				peer.Verify(true)
				notify = true
			}
		}
		if notify {
			Logger.Infof("Notifying peers of %q of list changes", user)
			err = hub.multicast(peers, map[string]interface{}{"peers": peers})
			if err != nil {
				msg := fmt.Sprintf("Failing notifying peers of changes: %s", err)
				Logger.Errorf(msg)
				http.Error(w, `{"msg": "`+msg+`"}`,
					http.StatusInternalServerError)
			}
		}

		w.Write([]byte(HTMLThankYou))
	}
}

func serveAuthPage(w http.ResponseWriter, r *http.Request) {
	i := strings.IndexRune(r.URL.Path[1:], '/')
	token := r.URL.Path[i+2:]
	user, err := db.GetToken(token)
	if err != nil || user == "" {
		Logger.Warnf("Got auth page request with bad token: err: %s, token: %s",
			err, token)
		http.Error(w, "Bad Token", http.StatusBadRequest)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := fmt.Sprintf("%s/auth.html", os.Getenv("PB_STATIC_ROOT"))
	http.ServeFile(w, r, p)
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
	if err != nil {
		http.Error(w, `{"m": "Bad JSON"}`, http.StatusBadRequest)
		return
	}
	if req["fp"] == "" {
		http.Error(w, `{"m": "Missing fp"}`, http.StatusBadRequest)
		return
	}
	if req["email"] == "" {
		http.Error(w, `{"m": "Missing email"}`, http.StatusBadRequest)
		return
	}
	peer, err := GetPeer(req["fp"])
	if err != nil {
		msg := fmt.Sprintf("Failed to get peer: %s", err)
		Logger.Errorf(msg)
		m, _ := json.Marshal(map[string]string{"m": msg})
		http.Error(w, string(m), http.StatusInternalServerError)
		return
	}
	if r.Method == "POST" {
		verified := peer.Verified && peer.User == req["email"]
		m, err := json.Marshal(map[string]bool{"verified": verified})
		if err != nil {
			msg := fmt.Sprintf("Failed to marshal user's list: %s", err)
			Logger.Errorf(msg)
			m, _ := json.Marshal(map[string]string{"m": msg})
			http.Error(w, string(m), http.StatusInternalServerError)
			return
		}
		w.Write(m)
		if !peer.Verified {
			peer := &Peer{FP: req["fp"], Name: req["name"],
				Kind: req["kind"], CreatedOn: time.Now().Unix(),
				User: req["email"], Verified: false, Online: true}
			db.AddPeer(peer)
			sendAuthEmail(req["email"])
			return
		}
		// update the name
		if peer.Name != req["name"] {
			peer.setName(req["name"])
		}
	}
}
func serveHome(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	if r.URL.Path != "/" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := fmt.Sprintf("%s/home.html", os.Getenv("PB_STATIC_ROOT"))
	http.ServeFile(w, r, p)
}

func initLogger() {
	// rotate the log file
	logWriter := &lumberjack.Logger{
		Filename:   "peerbook.log",
		MaxSize:    10, // megabytes
		MaxBackups: 3,
		MaxAge:     28, // days
	}
	w := zapcore.AddSync(logWriter)

	// TODO: use pion's logging
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
			MessageKey:  "webexec",
			LevelKey:    "level",
			EncodeLevel: zapcore.CapitalLevelEncoder,
			TimeKey:     "time",
			EncodeTime:  zapcore.ISO8601TimeEncoder,
		}),
		w,
		zapcore.InfoLevel,
	)
	logger := zap.New(core)
	defer logger.Sync()
	Logger = logger.Sugar()
	// redirect stderr
	e, _ := os.OpenFile(
		"peerbook.err", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	Dup2(int(e.Fd()), 2)
}

func startHTTPServer(addr string, wg *sync.WaitGroup) *http.Server {
	srv := &http.Server{
		Addr: addr, Handler: cors.Default().Handler(http.DefaultServeMux)}

	http.HandleFunc("/", serveHome)
	http.HandleFunc("/list/", serveList)
	http.HandleFunc("/auth/", serveAuthPage)
	http.HandleFunc("/verify", serveVerify)
	http.HandleFunc("/hitme", serveHitMe)
	http.HandleFunc("/ws", serveWs)

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

func main() {
	addr := flag.String("addr", "0.0.0.0:17777", "address to listen for http requests")
	redisH := flag.String("redis", "localhost:6379", "redis address")
	flag.Parse()
	if Logger == nil {
		initLogger()
	}
	err := db.Connect(*redisH)
	if err != nil {
		Logger.Errorf("Failed to connect to redis: %s", err)
		os.Exit(1)
	}

	hub = Hub{
		register:   make(chan *Peer),
		unregister: make(chan *Peer),
		peers:      make(map[string]*Peer),
		requests:   make(chan map[string]interface{}, 16),
	}
	go hub.run()

	httpServerExitDone := &sync.WaitGroup{}
	httpServerExitDone.Add(3)
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
