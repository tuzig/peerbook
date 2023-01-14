package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const credentialsURL = "https://api.subspace.com/v1/globalturn"
const tokenURL = "https://subspace.auth0.com/oauth/token"

// ICEServer is used to represent a STUN or TURN server
type ICEServer struct {
	// NOTE: in code it's URL, elsewhere it's urls as in w3c
	URL        string `redis:"urls" json:"urls"`
	Username   string `redis:"username" json:"username"`
	Credential string `redis:"credential" json:"credential"`
	Active     bool   `redis:"active" json:"-"`
}

func serveICEServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Only the POST method is supported", http.StatusBadRequest)
		return
	}
	servers, err := db.GetICEServers()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read ICESevers from db: %s", err),
			http.StatusInternalServerError)
		return
	}
	if len(servers) == 0 {
		http.Error(w, "No ICE servers found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("["))
	for i, s := range servers {
		b, err := json.Marshal(s)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to marshal ICE server: %s", err),
				http.StatusInternalServerError)
			return
		}
		if s.Active {
			w.Write(b)
			if i != len(servers)-1 {
				w.Write([]byte(","))
			}
		}
	}
	w.Write([]byte("]"))
}
