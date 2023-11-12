package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"github.com/tuzig/webexec/peers"
	"go.uber.org/zap/zaptest"
)

var lastPath string

func rcNotActiveHandler(w http.ResponseWriter, r *http.Request) {
	lastPath = path.Base(r.URL.Path)
	fmt.Fprint(w, rcNotActiveResponse)
}

func rcHandler(w http.ResponseWriter, r *http.Request) {
	lastPath = path.Base(r.URL.Path)
	fmt.Fprint(w, rcMockResponse)
}

/*
// test the register endpoint

	func TestRegister(t *testing.T) {
		// create a test user
		startTest(t)
		// prepare redis: add a temp user with a key "un:<last id>" value true
		redisDouble.Set("tempid:123", "1")
		// generate a request with a post to /register with the user's email, and
		// last id of 123
		// check the response is 200
		// check the response includes the QR code
		// check the user is in the db
		// HTTP post with a json body to local server with '123' as the last id
		// email as wile@acme.com and a random token
		msg := map[string]string{
			"email":      "wile@acme.com",
			"temp_id":    "123",
			"peer_name":  "molva",
			"fp":         "456",
			"public_key": "NOTUSED",
		}
		body, err := json.Marshal(msg)
		require.NoError(t, err)
		resp, err := http.Post("http://127.0.0.1:17777/register", "application/json",
			bytes.NewBuffer(body))
		require.NoError(t, err)
		defer resp.Body.Close()
		// check the response is 200 and if not print the body
		// body, err = io.ReadAll(resp.Body)
		// require.Equal(t, http.StatusOK, resp.StatusCode, "response body: %s", body)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		// json unmarashal the response body
		// check the response body has a qr code
		// check the user is in the db
		// check the user has the last id of 123
		// check the user has the fingerprint of 456
		// check the user has the public key of 789
		// check the user has the email of wile@acme.com
		// test the response body has a qr code
		var m map[string]string
		err = json.NewDecoder(resp.Body).Decode(&m)
		require.NoError(t, err)
		require.Contains(t, m, "QR")
		// test the response includes a userID
		require.Contains(t, m, "ID")
		// test the response includes a token
		require.Contains(t, m, "next_url")
		// validate next is a valid URL
		_, err = url.Parse(m["next_url"])
		require.NoError(t, err)
		userID := m["ID"]
		// get the secret from the db and generate a code
		secret, err := db.getUserSecret(userID)
		require.NoError(t, err)
		otp, err := totp.GenerateCode(secret, time.Now())
		require.Nil(t, err)
		// post to /qr/<token> a demo OTP
		// check the response is 200
		resp, err = http.PostForm("http://localhost:17777/qr/"+m["token"],
			url.Values{"otp": {otp}})
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "1", redisDouble.HGet("peer:456", "verified"))
		require.Equal(t, userID, redisDouble.HGet("peer:456", "user"))
		dbemail := redisDouble.HGet(fmt.Sprintf("user:%s", userID), "email")
		require.Equal(t, "wile@acme.com", dbemail)
		dbuser, err := redisDouble.Get("uid:wile@acme.com")
		require.NoError(t, err)
		require.Equal(t, userID, dbuser)
	}

	func TestRegisterBadTempID(t *testing.T) {
		var err error
		Logger = zaptest.NewLogger(t).Sugar()
		redisDouble, err = miniredis.Run()
		require.NoError(t, err)
		err = db.Connect("127.0.0.1:6379")
		require.NoError(t, err)
		// make sure 123 is not in the db
		redisDouble.Del("tempid:123")
		msg := map[string]string{
			"email":      "wile@acme.com",
			"temp_id":    "123",
			"peer_name":  "molva",
			"fp":         "456",
			"public_key": "NOTUSED",
		}
		// marshal the struct above to a reader
		body, err := json.Marshal(msg)
		require.NoError(t, err)
		req, err := http.NewRequest("POST", "/register", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}

		// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(serveRegister)

		// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
		// directly and pass in our Request and ResponseRecorder.
		handler.ServeHTTP(rr, req)

		require.Equal(t, http.StatusUnauthorized, rr.Code)
	}
*/
func TestAuthorizeAPeer(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	require.NoError(t, err)
	// generate a pair of public, private keys based on ed25519
	pub, _, err := ed25519.GenerateKey(rand.Reader)

	fp := "BADWOLDANDHISMOTERANDHISDOGTOO"
	redisDouble.SetAdd("userset:j", "A")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "client",
		"user", "j", "verified", "1", "public_key", base64.StdEncoding.EncodeToString(pub))
	redisDouble.HSet(`peer:${fp}`, "fp", fp, "name", "bar", "kind", "server",
		"user", "j", "verified", "0")

	req, err := http.NewRequest("POST", `/authorzie/${fp}`, nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(serveAuthorize)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "1", redisDouble.HGet(`peer:${fp}`, "verified"))
}
func TestBackendUnauthorized(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	require.NoError(t, err)
	b := NewUsersAuth()
	require.False(t, b.IsAuthorized("foo"))
}
func TestBackendAuthorized(t *testing.T) {
	var err error
	server := httptest.NewServer(http.HandlerFunc(rcHandler))
	defer server.Close()
	redisDouble, err = miniredis.Run()
	redisDouble.HSet("peer:foo", "fp", "foo", "verified", "1")
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	require.NoError(t, err)
	b := NewUsersAuth()
	b.rcURL = server.URL
	require.True(t, b.IsAuthorized("foo"))
}

var rcNotActiveResponse string = `{
	  "request_date": "2023-07-01T18:54:46Z",
	  "request_date_ms": 1688237686989,
	  "subscriber": {
		"subscriptions": {},
		"first_seen": "2023-06-27T05:41:40Z",
		"last_seen": "2023-07-01T17:40:19Z",
		"management_url": "https://apps.apple.com/account/subscriptions",
		"non_subscriptions": {},
		"original_app_user_id": "foo",
		"original_application_version": "1.0",
		"original_purchase_date": "2013-08-01T07:00:00Z",
		"other_purchases": {},
		"subscriber_attributes": {
		  "$attConsentStatus": {
			"updated_at_ms": 1687847082538,
			"value": "notDetermined"
		  }
		}
	  }
	}`
var rcMockResponse string = `{
	  "request_date": "2023-07-01T18:54:46Z",
	  "request_date_ms": 1688237686989,
	  "subscriber": {
		"entitlements": {
		  "peerbook": {
			"expires_date": "2023-07-01T19:03:06Z",
			"grace_period_expires_date": null,
			"product_identifier": "peerbook_monthly",
			"purchase_date": "2023-07-01T18:48:06Z"
		  }
		},
		"subscriptions": {
		  "peerbook_monthly": {
			"auto_resume_date": null,
			"billing_issues_detected_at": null,
			"expires_date": "2123-07-01T19:03:06Z",
			"grace_period_expires_date": null,
			"is_sandbox": true,
			"original_purchase_date": "2023-02-21T20:12:09Z",
			"ownership_type": "PURCHASED",
			"period_type": "normal",
			"purchase_date": "2023-07-01T18:48:06Z",
			"refunded_at": null,
			"store": "app_store",
			"unsubscribe_detected_at": null
		  }
		},
		"first_seen": "2023-06-27T05:41:40Z",
		"last_seen": "2023-07-01T17:40:19Z",
		"management_url": "https://apps.apple.com/account/subscriptions",
		"non_subscriptions": {},
		"original_app_user_id": "foo",
		"original_application_version": "1.0",
		"original_purchase_date": "2013-08-01T07:00:00Z",
		"other_purchases": {},
		"subscriber_attributes": {
		  "$attConsentStatus": {
			"updated_at_ms": 1687847082538,
			"value": "notDetermined"
		  }
		}
	  }
	}`

func testTempUIDActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(rcHandler))
	defer server.Close()
	active, err := isUIDActive("foo", server.URL)
	require.NoError(t, err)
	require.True(t, active)
	require.Equal(t, fmt.Sprintf("%s/v1/subscribers/foo", server.URL), lastPath)
	active, err = isUIDActive("bar", server.URL)
	require.False(t, active)
}

func TestBackendAuthorizeByBearer(t *testing.T) {
	var err error

	// Create a new instance of the test HTTP server
	server := httptest.NewServer(http.HandlerFunc(rcHandler))
	defer server.Close()
	Logger = zaptest.NewLogger(t).Sugar()
	redisDouble, err = miniredis.Run()
	redisDouble.HSet("peer:foo", "fp", "foo", "verified", "0")
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	require.NoError(t, err)
	b := NewUsersAuth()
	b.rcURL = server.URL
	require.True(t, b.IsAuthorized("bar", "foo"))
	verified, err := IsVerified("foo")
	require.NoError(t, err)
	require.False(t, verified)
}
func TestRegisterCommand(t *testing.T) {
	var err error
	Logger = zaptest.NewLogger(t).Sugar()
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	time.Sleep(time.Second / 100)
	require.NoError(t, err)
	_, err = GetPeer("A")
	require.NoError(t, err)
	b, err := register("A", "j@example.com", "yossi")
	Logger.Infof("Got %d bytes", len(b))
	var m map[string]string
	err = json.Unmarshal([]byte(b), &m)
	require.NoError(t, err)
	require.Contains(t, m, "ID")
	require.Equal(t, 16, len(m["ID"]))
	require.Contains(t, m, "QR")
	// make sure the m["ID"] is in the db
	email := redisDouble.HGet("user:"+m["ID"], "email")
	require.Equal(t, "j@example.com", email)
	id, err := redisDouble.Get("uid:" + email)
	require.NoError(t, err)
	require.Equal(t, m["ID"], id)
	require.Equal(t, "0", redisDouble.HGet("peer:A", "verified"))
}
func TestRegisterWExistingUser(t *testing.T) {
	var err error
	Logger = zaptest.NewLogger(t).Sugar()
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	redisDouble.SetAdd("userset:j", "A")
	redisDouble.HSet("user:j", "email", "j@example.com")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "fucked up", "kind", "client", "verified", "1")
	require.NoError(t, err)
	_, err = GetPeer("A")
	require.NoError(t, err)
	body, err := register("A", "j@example.com", "yossi")
	require.NoError(t, err)
	var m map[string]string
	err = json.Unmarshal([]byte(body), &m)
	require.NoError(t, err)
	require.Contains(t, m, "ID")
	require.Equal(t, "j", m["ID"])
	require.Contains(t, m, "QR")
}
func TestPingBadOTPCommand(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	redisDouble.SetAdd("userset:j", "A", "B")
	redisDouble.HSet("user:j", "email", "j@example.com")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "fucked up", "kind", "client", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "user", "j", "name", "fucked up", "kind", "server", "verified", "0")
	_, err = ping("A", "BADWOLF")
	require.Error(t, err)
}
func TestEmptyPing(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	redisDouble.SetAdd("userset:j", "A")
	redisDouble.HSet("user:j", "email", "j@example.com")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "fucked up", "kind", "client", "verified", "1")
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	result, err := ping("A", "")
	require.NoError(t, err)
	require.Equal(t, "j", string(result))
}
func TestPingCommand(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	redisDouble.SetAdd("userset:j", "A", "B")
	redisDouble.HSet("user:j", "email", "j@example.com")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "fucked up", "kind", "client", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "user", "j", "name", "fucked up", "kind", "server", "verified", "0")
	ok, err := getUserKey("j")
	require.NoError(t, err)
	otp, err := totp.GenerateCode(ok.Secret(), time.Now())
	require.NoError(t, err)
	ret, err := ping("A", otp)
	require.NoError(t, err)
	require.Equal(t, "1", string(ret))
}
func TestVerfifyCommand(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	redisDouble.SetAdd("userset:j", "A", "B")
	redisDouble.HSet("user:j", "email", "j@example.com")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "fucked up", "kind", "client", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "user", "j", "name", "fucked up", "kind", "server", "verified", "0")
	ok, err := getUserKey("j")
	require.NoError(t, err)
	otp, err := totp.GenerateCode(ok.Secret(), time.Now())
	require.NoError(t, err)
	err = verify("A", "B", otp)
	require.NoError(t, err)
	// make sure the peer is marked as verified
	require.Equal(t, "1", redisDouble.HGet("peer:B", "verified"))
}
func TestBadOTPVerfifyCommand(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	redisDouble.SetAdd("userset:j", "A", "B")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "fucked up", "kind", "client", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "user", "j", "name", "fucked up", "kind", "server", "verified", "0")
	err = verify("A", "B", "1233456")
	require.Error(t, err)
	require.Equal(t, "0", redisDouble.HGet("peer:B", "verified"))
}
func TestVerifyFreshPeer(t *testing.T) {
	var err error
	Logger = zaptest.NewLogger(t).Sugar()
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	redisDouble.FlushAll()
	redisDouble.SetAdd("userset:j", "A")
	redisDouble.HSet("user:j", "email", "j@example.com")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "fucked up", "kind", "client", "verified", "1")
	ok, err := getUserKey("j")
	require.NoError(t, err)
	otp, err := totp.GenerateCode(ok.Secret(), time.Now())
	require.NoError(t, err)
	err = verify("A", "B", otp)
	require.NoError(t, err)
}
func TestRegisterCommandWithExistingUser(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
}
func TestQRSixel(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	// to generate a sixel image we need a user with a QR code
	redisDouble.SetAdd("userset:j", "A", "B")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "1", "online", "0")
	redisDouble.HSet("peer:B", "fp", "B", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0", "online", "0")
	ok, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Peerbbook",
		AccountName: "j",
	})
	require.Nil(t, err)
	// otp, err := totp.GenerateCode(ok.Secret(), time.Now())
	// require.Nil(t, err)
	redisDouble.HSet("user:j", "email", "j@example.com", "secret", ok.Secret())
	sixel, err := GetQRSixel("j")
	require.NoError(t, err)
	require.NotEmpty(t, sixel)
}
func TestDeleteCommand(t *testing.T) {
	var err error
	Logger = zaptest.NewLogger(t).Sugar()
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	redisDouble.SetAdd("userset:j", "A", "B")
	redisDouble.HSet("user:j", "email", "j@example.com")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "fucked up", "kind", "client", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "user", "j", "name", "fucked up", "kind", "server", "verified", "0")
	ok, err := getUserKey("j")
	require.NoError(t, err)
	otp, err := totp.GenerateCode(ok.Secret(), time.Now())
	require.NoError(t, err)
	err = deletePeer("A", "B", otp)
	require.NoError(t, err)
	// make sure the peer is marked as verified
	require.Equal(t, false, redisDouble.Exists("peer:B"))
	isMember, err := redisDouble.SIsMember("userset:j", "B")
	require.NoError(t, err)
	require.False(t, isMember)
}
func TestDeleteCommandBadOTP(t *testing.T) {
	var err error
	Logger = zaptest.NewLogger(t).Sugar()
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	redisDouble.SetAdd("userset:j", "A", "B")
	redisDouble.HSet("user:j", "email", "j@example.com")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "fucked up", "kind", "client", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "user", "j", "name", "fucked up", "kind", "server", "verified", "0")
	err = deletePeer("A", "B", "123456")
	require.Error(t, err)
	require.True(t, redisDouble.Exists("peer:B"))
}
func TestRenameCommand(t *testing.T) {
	var err error
	Logger = zaptest.NewLogger(t).Sugar()
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	redisDouble.SetAdd("userset:j", "A", "B")
	redisDouble.HSet("user:j", "email", "j@example.com")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "fucked up", "kind", "client", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "user", "j", "name", "fucked up", "kind", "server", "verified", "0")
	err = rename("A", "A", "behind all")
	require.NoError(t, err)
	require.Equal(t, "behind all", redisDouble.HGet(`peer:A`, "name"))
}
func TestRenameCommandBadTarget(t *testing.T) {
	var err error
	Logger = zaptest.NewLogger(t).Sugar()
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	redisDouble.SetAdd("userse:j", "A")
	redisDouble.HSet("user:j", "email", "j@example.com")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "fucked up", "kind", "client", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "user", "k", "name", "fucked up", "kind", "server", "verified", "0")
	err = rename("A", "B", "behind all")
	require.Error(t, err)
}

func TestOfferCommandBadTarget(t *testing.T) {
	startTest(t)
	err := db.Connect("127.0.0.1:6379")
	redisDouble.SetAdd("userset:j", "A")
	redisDouble.HSet("user:j", "email", "j@example.com")
	redisDouble.HSet("peer:A", "_p", "A", "user", "j", "name", "foo", "kind", "client", "verified", "1")
	server := httptest.NewServer(http.HandlerFunc(rcHandler))
	defer server.Close()
	err = forwardSDP("A", "B", "offer", json.RawMessage{})
	require.Error(t, err)
}
func TestOfferCommand(t *testing.T) {
	var err error
	startTest(t)
	err = db.Connect("127.0.0.1:6379")
	redisDouble.SetAdd("userset:j", "A", "B")
	redisDouble.HSet("user:j", "email", "j@example.com")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "foo", "kind", "client", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "user", "j", "name", "bar", "kind", "server", "verified", "1")
	server := httptest.NewServer(http.HandlerFunc(rcHandler))
	defer server.Close()
	os.Setenv("REVENUECAT_URL", server.URL)
	wsB, _, err := openWS("ws://127.0.0.1:17777/ws?fp=B&name=bar&kind=lay&uid=j")
	require.Nil(t, err)
	defer wsB.Close()
	if err = wsB.SetReadDeadline(time.Now().Add(ReadTimeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var m map[string]interface{}
	// first message is the peers
	err = wsB.ReadJSON(&m)
	require.NoError(t, err)
	require.Nil(t, err)
	// second message is a peer_update
	err = wsB.ReadJSON(&m)
	require.Nil(t, err)
	peers.Peers = make(map[string]*peers.Peer)
	peers.Peers["A"] = &peers.Peer{
		FP: "A",
	}

	err = forwardSDP("A", "B", "offer", json.RawMessage(`"an offer"`))
	require.NoError(t, err)
	var o OfferMessage
	err = wsB.ReadJSON(&o)
	require.Equal(t, "an offer", o.Offer)
}

func TestAnswerMessage(t *testing.T) {
	var m sync.Mutex
	var answer AnswerMessage
	startTest(t)
	server := httptest.NewServer(http.HandlerFunc(rcNotActiveHandler))
	defer server.Close()
	os.Setenv("REVENUECAT_URL", server.URL)
	err := db.Connect("127.0.0.1:6379")
	redisDouble.SetAdd("userset:j", "A", "B")
	redisDouble.HSet("user:j", "email", "j@example.com")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "foo", "kind", "client", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "user", "j", "name", "bar", "kind", "server", "verified", "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sendMessage := func(msg []byte) error {
		// if the msg is a string, unmarshal the json
		s := string(msg)
		m.Lock()
		err := json.Unmarshal([]byte(s), &answer)
		m.Unlock()
		require.NoError(t, err)
		return nil
	}
	go sender(ctx, "A", sendMessage)
	wsB, _, err := openWS("ws://127.0.0.1:17777/ws?fp=B&name=bar&kind=lay&uid=j")
	require.NoError(t, err)
	defer wsB.Close()
	err = wsB.SetWriteDeadline(time.Now().Add(WriteTimeout))
	require.NoError(t, err)
	err = wsB.WriteJSON(map[string]string{"answer": "B's answer", "target": "A"})
	require.NoError(t, err)
	time.Sleep(time.Second / 10)
	m.Lock()
	require.Equal(t, "B's answer", answer.Answer)
	require.Equal(t, "B", answer.SourceFP)
	m.Unlock()
}
