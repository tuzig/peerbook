package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/pion/webrtc/v3"
	"github.com/twilio/twilio-go"
	tapi "github.com/twilio/twilio-go/rest/api/v2010"
)

var now = time.Now

// ICEServer is used to represent a STUN or TURN server
type ICEServer struct {
	Url        string `redis:"url" json:"url,omitempty"`
	Username   string `redis:"username" json:"username,omitempyy"`
	Credential string `redis:"-" json:"credential,omitempyy"`
	Active     bool   `redis:"active" json:"-"`
	Urls       string `redis:"urls" json:"urls,omitempty"`
}

// genCredential returns a username and credential for a TURN server
// based on the username and the secret key
func genCredential(username string) (string, string) {
	secretKey := os.Getenv("TURN_SECRET_KEY")
	if secretKey == "" {
		secretKey = "thisisatest"
	}
	h := hmac.New(sha1.New, []byte(secretKey))
	timestamp := now().Add(24 * time.Hour).Unix()
	compuser := fmt.Sprintf("%d:%s", timestamp, username)
	_, _ = h.Write([]byte(compuser))
	// return the compound username and the base64 encoded HMAC-SHA1
	return compuser, base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func serveICEServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Only the POST method is supported", http.StatusBadRequest)
		return
	}
	servers, err := GetICEServers()
	// return the JSON representation of the servers
	if servers == nil {
		servers = []webrtc.ICEServer{}
	}
	b, err := json.Marshal(servers)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to marshal servers: %s", err),
			http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func getTwilio() ([]ICEServer, error) {
	client := twilio.NewRestClient()
	params := &tapi.CreateTokenParams{}
	token, err := client.Api.CreateToken(params)
	if err != nil {
		return nil, err
	}
	var ret []ICEServer
	for _, iceServer := range *token.IceServers {
		ret = append(ret, ICEServer{
			Url:        iceServer.Url,
			Urls:       iceServer.Urls,
			Username:   iceServer.Username,
			Credential: iceServer.Credential,
		})
	}
	return ret, nil
}

// GetICEServers returns all the ICE servers from twilio
func GetICEServers() ([]webrtc.ICEServer, error) {
	var iceservers []webrtc.ICEServer
	servers, err := db.GetICEServers()
	if err != nil {
		Logger.Errorf("Failed to get ICE servers from db: %s", err)
	} else {
		// Add creredentials to the servers
		for i, server := range servers {
			servers[i].Username, servers[i].Credential = genCredential(server.Username)
		}
	}
	if os.Getenv("TWILIO_AUTH_TOKEN") != "" {
		twilioServers, err := getTwilio()
		if err != nil {
			Logger.Errorf("Failed to get ICE servers from twilio: %s", err)
		} else {
			servers = append(servers, twilioServers...)
		}
		for _, s := range servers {
			iceservers = append(iceservers, webrtc.ICEServer{
				URLs:           []string{s.Urls},
				Username:       s.Username,
				Credential:     s.Credential,
				CredentialType: webrtc.ICECredentialTypePassword,
			})
		}
	} else {
		Logger.Warn("TWILIO_AUTH_TOKEN not set, using local TURN servers: %v", servers)
	}
	return iceservers, nil
}
