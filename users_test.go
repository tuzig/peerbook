package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

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
	secret, err := getUserSecret(userID)
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
	dbemail := redisDouble.HGet(fmt.Sprintf("u:%s", userID), "email")
	require.Equal(t, "wile@acme.com", dbemail)
	dbuser, err := redisDouble.Get("id:wile@acme.com")
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
func TestAuthorizeAPeer(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	require.NoError(t, err)
	// generate a pair of public, private keys based on ed25519
	pub, _, err := ed25519.GenerateKey(rand.Reader)

	fp := "BADWOLDANDHISMOTERANDHISDOGTOO"
	redisDouble.SetAdd("user:j", "A")
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
func TestRevenuCatWH(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	require.NoError(t, err)
	msg := RCWebhookEvent{
		Event: RCEvent{AppUserID: "123", Type: "INITIAL_PURCHASE"},
	}
	body, err := json.Marshal(msg)
	req, err := http.NewRequest("POST", "/rcwh", bytes.NewReader(body))
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(serveRCWH)
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	v, err := redisDouble.Get("tempid:123")
	require.NoError(t, err)
	require.Equal(t, "1", v)
}
func TestBackendAuthorized(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	require.NoError(t, err)
	b := NewUsersAuth()
	require.False(t, b.IsAuthorized("foo"))
}
func TestBackendUnAuthorized(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	redisDouble.Set("peer:foo", "1")
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	require.NoError(t, err)
	b := NewUsersAuth()
	require.True(t, b.IsAuthorized("foo"))
}
func TestBackendAuthorizedTempID(t *testing.T) {
	var err error
	Logger = zaptest.NewLogger(t).Sugar()
	redisDouble, err = miniredis.Run()
	redisDouble.Set("tempid:bar", "1")
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	require.NoError(t, err)
	b := NewUsersAuth()
	require.True(t, b.IsAuthorized("foo", "bar"))
	verified, err := IsVerified("foo")
	require.NoError(t, err)
	require.True(t, verified)
}
func TestRegisterCommand(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	redisDouble.HSet("peer:A", "fp", "A", "name", "fucked up", "kind", "client", "verified", "1")
	require.NoError(t, err)
	_, err = GetPeer("A")
	require.NoError(t, err)
	_, f, err := RunCommand([]string{"register", "j@example.com", "yossi"}, nil, nil, 0, "A")
	require.NoError(t, err)
	require.NotNil(t, f)
	b, err := ioutil.ReadAll(f)
	require.NoError(t, err)
	var m map[string]string
	err = json.Unmarshal(b, &m)
	require.NoError(t, err)
	require.Contains(t, m, "ID")
	require.Contains(t, m, "QR")
	// make sure the m["ID"] is in the db
	email := redisDouble.HGet("u:"+m["ID"], "email")
	require.Equal(t, "j@example.com", email)
	id, err := redisDouble.Get("id:" + email)
	require.NoError(t, err)
	require.Equal(t, m["ID"], id)
}
func TestPingBadOTPCommand(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("u:j", "email", "j@example.com")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "fucked up", "kind", "client", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "user", "j", "name", "fucked up", "kind", "server", "verified", "0")
	_, f, err := RunCommand([]string{"ping", "BADWOLF"}, nil, nil, 0, "A")
	result, err := ioutil.ReadAll(f)
	require.NoError(t, err)
	require.Equal(t, byte('0'), result[0])
}
func TestForPong(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	_, f, err := RunCommand([]string{"ping"}, nil, nil, 0, "A")
	result, err := ioutil.ReadAll(f)
	require.NoError(t, err)
	require.Equal(t, "pong", string(result))
}
func TestPingCommand(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("u:j", "email", "j@example.com")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "fucked up", "kind", "client", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "user", "j", "name", "fucked up", "kind", "server", "verified", "0")
	ok, err := getUserKey("j")
	require.NoError(t, err)
	otp, err := totp.GenerateCode(ok.Secret(), time.Now())
	require.NoError(t, err)
	_, f, err := RunCommand([]string{"ping", otp}, nil, nil, 0, "A")
	result, err := ioutil.ReadAll(f)
	require.NoError(t, err)
	require.Equal(t, byte('1'), result[0])
}
func TestAuthorizeCommand(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("u:j", "email", "j@example.com")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "fucked up", "kind", "client", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "user", "j", "name", "fucked up", "kind", "server", "verified", "0")
	ok, err := getUserKey("j")
	require.NoError(t, err)
	otp, err := totp.GenerateCode(ok.Secret(), time.Now())
	require.NoError(t, err)
	cmd, f, err := RunCommand([]string{"authorize", "B", otp}, nil, nil, 0, "A")
	require.NoError(t, err)
	require.Nil(t, f)
	require.Nil(t, cmd)
	require.Equal(t, "1", redisDouble.HGet("peer:B", "verified"))
}
func TestBadOTPAuthorizeCommand(t *testing.T) {
	var err error
	redisDouble, err = miniredis.Run()
	require.NoError(t, err)
	err = db.Connect("127.0.0.1:6379")
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("peer:A", "fp", "A", "user", "j", "name", "fucked up", "kind", "client", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "user", "j", "name", "fucked up", "kind", "server", "verified", "0")
	cmd, f, err := RunCommand([]string{"authorize", "B", "1233456"}, nil, nil, 0, "A")
	require.NotNil(t, err)
	require.Nil(t, f)
	require.Nil(t, cmd)
	require.Equal(t, "0", redisDouble.HGet("peer:B", "verified"))
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
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("u:j", "email", "j@example.com")
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
	redisDouble.Set("secret:j", ok.Secret())
	sixel, err := GetQRSixel("j")
	require.NoError(t, err)
	require.NotEmpty(t, sixel)
}
