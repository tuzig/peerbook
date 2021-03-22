// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"log"
	"net/http"
	"os"
)

// Logger is our global logger
var (
	Logger *zap.SugaredLogger
)

type PeerNotFound struct{}

func (p *PeerNotFound) Error() string {
	return "Peer not found"
}

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
func main() {
	flag.Parse()
	if Logger == nil {
		initLogger()
	}
	hub := newHub("localhost:6379")
	defer hub.Close()
	go hub.run()
	http.HandleFunc("/", serveHome)
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})
	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		Logger.Errorf("ListenAndServe failed: ", err)
	}
}
