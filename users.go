package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"net/http"
	"net/url"
	"strings"
)

type subscriberAttributes map[string]subscriberAttribute

// SubscriberAttribute represents attributes of subscriber.
type subscriberAttribute struct {
	Value     string `json:"value"`
	UpdatedAt int    `json:"updated_at_ms"`
}

// RCWebhookEvent represents a RevenueCat webhook event
type RCWebhookEvent struct {
	Event      RCEvent `json:"event"`
	APIVersion string  `json:"api_version"`
}

// Event represents an Event of RevenueCat webhook
type RCEvent struct {
	ID                       string               `json:"id,omitempty"`
	Type                     string               `json:"type,omitempty"`
	EventTimestampAt         int                  `json:"event_timestamp_ms,omitempty"`
	AppUserID                string               `json:"app_user_id,omitempty"`
	Aliases                  []string             `json:"aliases,omitempty"`
	OriginalAppUserID        string               `json:"original_app_user_id,omitempty"`
	ProductID                string               `json:"product_id,omitempty"`
	EntitlementIDs           []string             `json:"entitlement_ids,omitempty"`
	PeriodType               string               `json:"period_type,omitempty"`
	PurchasedAt              int                  `json:"purchased_at_ms,omitempty"`
	GracePeriodExpirationAt  int                  `json:"grace_period_expiration_at_ms,omitempty"`
	ExpirationAt             int                  `json:"expiration_at_ms,omitempty"`
	AutoResumeAt             int                  `json:"auto_resume_at_ms,omitempty"`
	Store                    string               `json:"store,omitempty"`
	Environment              string               `json:"environment,omitempty"`
	IsTrialConversion        bool                 `json:"is_trial_conversion,omitempty"`
	CancelReason             string               `json:"cancel_reason,omitempty"`
	ExpirationReason         string               `json:"expiration_reason,omitempty"`
	NewProductID             string               `json:"new_product_id,omitempty"`
	PresentedOfferingID      string               `json:"presented_offering_id,omitempty"`
	Price                    float64              `json:"price,omitempty"`
	Currency                 string               `json:"currency,omitempty"`
	PriceInPurchasedCurrency float32              `json:"price_in_purchased_currency,omitempty"`
	TakeHomePercentage       float32              `json:"takehome_percentage,omitempty"`
	SubscriberAttributes     subscriberAttributes `json:"subscriber_attributes,omitempty"`
	TransactionID            string               `json:"transaction_id,omitempty"`
	OriginalTransactionID    string               `json:"original_transaction_id,omitempty"`
	OfferCode                string               `json:"offer_code,omitempty"`
}

func GetQRImage(user string) (string, error) {
	var qr bytes.Buffer
	ok, err := getUserKey(user)
	if err != nil {
		return "", fmt.Errorf("Failed to get users secret key QR iomage: %S", err)
	}
	img, err := ok.Image(200, 200)
	if err != nil {
		return "", fmt.Errorf("Failed to get the QR image: %S", err)
	}
	encoder := base64.NewEncoder(base64.StdEncoding, &qr)
	defer encoder.Close()
	png.Encode(encoder, img)
	return qr.String(), nil
}

// serveRegister handles the registration of a new user
// it will return a 200 if the user is registered
// it will get a json encoded user witht the following fields:
// - email
// - temp_id
// - peer_name
// - fp
// - public_key
// If will allocate a random permenet ID for the user and
// store it and the email in the db. It will add a new peer
// fith the fp & public key and return 200 with the following fields:
// - QR
// - ID
// - token
func serveRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// get the json body
	// check the body has the correct fields
	// check the temp_id is in the db
	// check the email is not in the db
	// check the fingerprint is not in the db
	// check the public key is not in the db
	// generate a random permenent ID
	defer r.Body.Close()
	// get the fields from the body to a map
	var m map[string]string
	err := json.NewDecoder(r.Body).Decode(&m)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// check the map has the correct fields
	// check the temp_id is in the db
	// check the email is not in the db
	// check the fingerprint is not in the db
	if _, ok := m["email"]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("email is missing"))
		return
	}
	if _, ok := m["temp_id"]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("temp_id is missing"))
		return
	}
	if _, ok := m["fp"]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("fp is missing"))
		return
	}
	if _, ok := m["public_key"]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("public_key is missing"))
		return
	}
	if _, ok := m["peer_name"]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("peer_name is missing"))
		return
	}
	// check the temp_id is in the db
	exists, err := db.tempIDExists(m["temp_id"])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed to check temp_id - %s", err)))
		return
	}
	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("temp_id is not known"))
		return
	}
	// add the user
	// generate a random permenent ID
	// add the user to the db
	uID, err := db.AddUser(m["email"])
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to add user - %s", err),
			http.StatusInternalServerError)
		return
	}
	peer := NewPeer(m["fp"], m["peer_name"], uID, "client", m["public_key"])
	peer.Verified = true
	err = db.AddPeer(peer)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to add peer - %s", err),
			http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	next, err := createTempURL(uID, "qr", true)
	// write a json encoded response with the following fields:
	// - QR
	// - ID
	// - token
	img, err := GetQRImage(uID)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate QR code - %s", err),
			http.StatusInternalServerError)
		return
	}
	resp := map[string]string{
		// TODO: add the QR code
		"QR":       img,
		"ID":       uID,
		"next_url": next,
	}
	json.NewEncoder(w).Encode(resp)
}

// serveAuthorize handles the authorization of a peer
// it will return a 200 if the peer is authorized
func serveAuthorize(w http.ResponseWriter, r *http.Request) {
	i := strings.IndexRune(r.URL.Path[1:], '/')
	t := r.URL.Path[i+2:]
	fp, err := url.PathUnescape(t)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Failed to unescape token: err: %s", err)))
		return
	}
	// check the fingerprint is in the db
	exists, err := db.PeerExists(fp)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("fingerprint is not known"))
		return
	}
	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("fingerprint is not known"))
		return
	}
	err = VerifyPeer(fp, true)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed to verify peer - %s", err)))
		return
	}
}

// serveRCWH handles revenuecat webhooks
func serveRCWH(w http.ResponseWriter, r *http.Request) {
	var whevent RCWebhookEvent

	err := json.NewDecoder(r.Body).Decode(&whevent)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to decode webhook - %s", err),
			http.StatusBadRequest)
		return
	}
	event := whevent.Event
	switch event.Type {
	case "INITIAL_PURCHASE":
		// add the user's temp_id to the db
		db.AddTempID(event.AppUserID)
		break
	case "EXPIRATION":
		// mark the user as inactive
		db.SetUserActive(event.AppUserID, false)
		break
	}

}
