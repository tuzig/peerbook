// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
)

// Logger is our global logger
var (
	Logger *zap.SugaredLogger
	stop   chan os.Signal
)

// UnauthorizedPeer is an error
type UnauthorizedPeer struct {
	peer *Peer
}

func (e *UnauthorizedPeer) Error() string {
	return fmt.Sprintf("An unathenticated peer tried to connect - %v", e.peer)
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

var addr = flag.String("addr", "0.0.0.0:17777", "http service address")

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
	http.ServeFile(w, r, "home.html")
}

func initLogger() {
	// rotate the log file
	logWriter := &lumberjack.Logger{
		Filename:   "peerbppk.log",
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
func startHTTPServer(hub *Hub, wg *sync.WaitGroup) *http.Server {
	srv := &http.Server{Addr: *addr}

	http.HandleFunc("/", serveHome)
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})

	go func() {
		defer wg.Done() // let main know we are done cleaning up

		// always returns error. ErrServerClosed on graceful close
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			// unexpected error. port in use?
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	// returning reference so caller can call Shutdown()
	return srv
}

func main() {
	flag.Parse()
	if Logger == nil {
		initLogger()
	}
	redisConnect("localhost:6379")
	defer redisConn.Close()

	hub := newHub()
	go hub.run()

	httpServerExitDone := &sync.WaitGroup{}
	httpServerExitDone.Add(3)
	srv := startHTTPServer(hub, httpServerExitDone)
	// Setting up signal capturing
	stop = make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	if err := srv.Shutdown(context.Background()); err != nil {
		Logger.Error("failure/timeout shutting down the http server gracefully")
	}
	// wait for goroutine started in startHTTPServer() to stop
	httpServerExitDone.Wait()
}
