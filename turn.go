package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

const credentialsURL = "https://api.subspace.com/v1/globalturn"
const tokenURL = "https://subspace.auth0.com/oauth/token"

type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
}

func serveTURN(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Only th POST method is supported", http.StatusBadRequest)
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
		w.Write(b)
		if i != len(servers)-1 {
			w.Write([]byte(","))
		}
	}
	w.Write([]byte("]"))
}

func getSubspaceToken() (string, error) {
	subspaceId := os.Getenv("SUBSPACE_ID")
	if subspaceId == "" {
		return "", fmt.Errorf("SUBSPACE_ID is not set")
	}
	msg := map[string]string{
		"client_id":     subspaceId,
		"client_secret": os.Getenv("SUBSPACE_SECRET"),
		"audience":      "https://api.subspace.com/",
		"grant_type":    "client_credentials"}
	m, err := json.Marshal(msg)
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Post(tokenURL, "application/json", bytes.NewBuffer(m))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Got error %d from subspace", resp.StatusCode)
	}
	var ret map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&ret)
	if err != nil {
		Logger.Warnf("Failed to get subspace token: %s", err)
		http.Error(w, fmt.Sprintf("Failed to get token: %s", err),
			http.StatusInternalServerError)
		return
	}
	t = ret["access_token"].(string)
	// TODO cache the bearerAuth using redis
	bearerAuth := fmt.Sprintf("Bearer %s", t)
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	req, err := http.NewRequest("POST", credentialsURL, nil)
	if err != nil {
		return "", fmt.Errorf("Failed to get redetials from subspace: %s", err)
	}
	req.Header.Add("authorization", bearerAuth)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Failed to get turn server")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		Logger.Warn("Our TURN credentials are outdates")
		return "", fmt.Errorf("Uauthorized on the TURN service")
	}
	return bearerAuth, nil
}
