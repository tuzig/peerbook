package main

import (
	"encoding/json"
	"fmt"
	"net/http"
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

// serveRCWH handles revenuecat webhooks
func serveRCWH(w http.ResponseWriter, r *http.Request) {
	var whevent RCWebhookEvent

	err := json.NewDecoder(r.Body).Decode(&whevent)
	if err != nil {
		Logger.Warnf("failed to decode revenue cat event - %s", err)
		http.Error(w, fmt.Sprintf("failed to decode webhook - %s", err),
			http.StatusBadRequest)
		return
	}
	event := whevent.Event
	switch event.Type {
	case "INITIAL_PURCHASE":
		// add the user's temp_id to the db
		Logger.Infof("adding temp id %s", event.AppUserID)
		db.AddTempID(event.AppUserID)
		break
	case "EXPIRATION":
		// mark the user as inactive
		Logger.Infof("user subscription expired %s", event.AppUserID)
		db.SetUserActive(event.AppUserID, false)
		break
	}

}
