package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

var bearerAuth string

const credentialsURL = "https://api.subspace.com/v1/globalturn"
const tokenURL = "https://subspace.auth0.com/oauth/token"

func serveTURN(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		http.Error(w, "Only th POST method is supported", http.StatusBadRequest)
	}
	if bearerAuth == "" {
		t, err := getTURNToken()
		if err != nil {
			Logger.Warnf("subspace to get subspace token: %s", err)
			http.Error(w, fmt.Sprintf("Failed to get token: %s", err),
				http.StatusInternalServerError)
			return
		}
		bearerAuth = fmt.Sprintf("Bearer %s", t)
	}
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	req, err := http.NewRequest("POST", credentialsURL, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get redetials from subspace: %s", err),
			http.StatusInternalServerError)
	}
	req.Header.Add("authorization", bearerAuth)
	resp, err := client.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		Logger.Info("Requesting a new subspace token")
		bearerAuth = ""
		serveTURN(w, r)
		return
	}
	b, _ := io.ReadAll(resp.Body)
	w.Write(b)
}

func getTURNToken() (string, error) {
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
	return ret["access_token"].(string), nil
}
