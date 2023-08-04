package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v3"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"github.com/tuzig/webexec/httpserver"
	"github.com/tuzig/webexec/peers"
	"go.uber.org/zap/zaptest"
	"golang.org/x/net/html"
)

const ReadTimeout = time.Second * 3
const WriteTimeout = time.Second

var cstDialer = websocket.Dialer{
	ReadBufferSize:   1024,
	WriteBufferSize:  1024,
	HandshakeTimeout: 30 * time.Second,
}

var mainRunning bool

func startTest(t *testing.T) {
	if !mainRunning {
		var err error
		Logger = zaptest.NewLogger(t).Sugar()
		redisDouble, err = miniredis.Run()
		require.NoError(t, err)
		go main()
		mainRunning = true
	} else {
		redisDouble.FlushAll()
	}
	time.Sleep(time.Millisecond * 10)
}
func openWS(url string) (*websocket.Conn, *http.Response, error) {
	time.Sleep(time.Millisecond)
	ws, resp, err := cstDialer.Dial(url, nil)
	return ws, resp, err
}
func newClient(t *testing.T) (*webrtc.PeerConnection, *webrtc.Certificate, error) {
	secretKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := webrtc.GenerateCertificate(secretKey)
	certs := []webrtc.Certificate{*certificate}
	client, err := webrtc.NewPeerConnection(
		webrtc.Configuration{Certificates: certs})
	if err != nil {
		return nil, nil, err
	}
	return client, certificate, err
}
func TestBadConnectionRequest(t *testing.T) {
	startTest(t)
	// create client, connect to the hu
	url := "ws://127.0.0.1:17777/ws"
	_, resp, err := cstDialer.Dial(url, nil)
	require.NotNil(t, err)
	require.Equal(t, resp.StatusCode, 400)
}
func TestUnknownFingerprint(t *testing.T) {
	startTest(t)
	// setup a mock revenuecat server
	server := httptest.NewServer(http.HandlerFunc(rcNotActiveHandler))
	defer server.Close()
	os.Setenv("REVENUECAT_URL", server.URL)
	// create client, connect to the hu
	ws, _, err := openWS("ws://127.0.0.1:17777/ws?fp=BADWOLF&uid=1234567890")
	require.Nil(t, err)
	var m map[string]interface{}
	err = ws.ReadJSON(&m)
	require.Nil(t, err)
	require.Equal(t, float64(401), m["code"].(float64), "msg: %v", m)
}
func TestSignalingAcrossUsers(t *testing.T) {
	startTest(t)
	redisDouble.HSet("u:j", "email", "j@example.com")
	redisDouble.HSet("u:h", "email", "h@example.com")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "name", "bar", "kind", "lay",
		"user", "h", "verified", "1")
	redisDouble.SetAdd("user:j", "A")
	redisDouble.SetAdd("user:h", "B")
	// setup a mock revenuecat server
	server := httptest.NewServer(http.HandlerFunc(rcHandler))
	defer server.Close()
	os.Setenv("REVENUECAT_URL", server.URL)
	// create client, connect to the hu
	wsA, _, err := openWS("ws://127.0.0.1:17777/ws?fp=A&name=foo&kind=lay&uid=j")
	require.Nil(t, err)
	defer wsA.Close()
	if err = wsA.SetReadDeadline(time.Now().Add(ReadTimeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	wsB, _, err := openWS("ws://127.0.0.1:17777/ws?fp=B&name=bar&kind=lay&uid=h")
	require.Nil(t, err)
	defer wsB.Close()
	if err = wsB.SetReadDeadline(time.Now().Add(ReadTimeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	// clean the pipe by reading the first three peers messages
	var pl map[string]interface{}
	time.Sleep(time.Second / 5)
	err = wsA.ReadJSON(&pl)
	require.Nil(t, err)
	require.Contains(t, pl, "peers")
	peers := pl["peers"].([]interface{})
	require.Equal(t, 1, len(peers))
	uid := pl["uid"].(string)
	require.Equal(t, "j", uid)
	err = wsA.ReadJSON(&pl)
	require.Nil(t, err)
	require.Contains(t, pl, "peer_update")
	err = wsB.ReadJSON(&pl)
	require.Nil(t, err)
	require.Contains(t, pl, "peers")
	err = wsB.ReadJSON(&pl)
	require.Nil(t, err)
	require.Contains(t, pl, "peer_update")
	err = wsA.SetWriteDeadline(time.Now().Add(time.Second))
	require.Nil(t, err)
	// send the offer
	err = wsA.WriteJSON(map[string]string{"offer": "an offer", "target": "B"})
	require.Nil(t, err)
	var m map[string]interface{}
	err = wsA.ReadJSON(&m)
	require.Nil(t, err)
	require.Equal(t, float64(401), m["code"].(float64), "msg: %v", m)
	err = wsB.ReadJSON(&m)
	require.NotNil(t, err, "Got message %v", m)
}

// TestValidSignaling runs through the following steps:
// - setup db with user J and his A & B peers
// - use websockets to connect A and then B
// - peer A reads to two peers messages
// - peer B reads a peers message
// - peer A send an offer
// - peer B recieves the offer
// - peer B send an answer
// - peer A recieves the answer
func TestValidSignaling(t *testing.T) {
	startTest(t)
	startTime := time.Now().Unix()
	redisDouble.HSet("u:j", "email", "j@example.com")
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "1", "online", "0")
	redisDouble.HSet("peer:B", "fp", "B", "name", "bar", "kind", "lay",
		"user", "j", "verified", "1", "online", "0")
	// setup a mock revenuecat server
	server := httptest.NewServer(http.HandlerFunc(rcHandler))
	defer server.Close()
	os.Setenv("REVENUECAT_URL", server.URL)
	// create client, connect to the hu
	wsA, _, err := openWS("ws://127.0.0.1:17777/ws?fp=A&name=foo&kind=lay&uid=j")
	require.Nil(t, err)
	defer wsA.Close()
	if err = wsA.SetReadDeadline(time.Now().Add(ReadTimeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	wsB, _, err := openWS("ws://127.0.0.1:17777/ws?fp=B&name=bar&kind=lay&uid=j")
	require.Nil(t, err)
	defer wsB.Close()
	if err = wsB.SetReadDeadline(time.Now().Add(ReadTimeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	// read all the peers messages
	var m map[string]interface{}
	err = wsA.ReadJSON(&m)
	require.Nil(t, err)
	require.Contains(t, m, "peers")
	require.Contains(t, m, "uid")
	err = wsA.ReadJSON(&m)
	require.Nil(t, err)
	require.Contains(t, m, "peer_update")
	err = wsB.ReadJSON(&m)
	require.Nil(t, err)
	require.Contains(t, m, "peers")
	require.Contains(t, m, "uid")
	err = wsB.ReadJSON(&m)
	require.Nil(t, err)
	require.Contains(t, m, "peer_update")
	// end of peers messages
	err = wsA.SetWriteDeadline(time.Now().Add(WriteTimeout))
	require.Nil(t, err)
	err = wsA.WriteJSON(map[string]string{"offer": "an offer", "target": "B"})
	require.Nil(t, err)
	var msg map[string]interface{}
	err = wsB.ReadJSON(&msg)
	require.Nil(t, err)
	require.Equal(t, "an offer", msg["offer"], "Got a msg: %v", msg)
	err = wsB.SetWriteDeadline(time.Now().Add(WriteTimeout))
	require.Nil(t, err)
	err = wsB.WriteJSON(map[string]string{"answer": "B's answer", "target": "A"})
	require.Nil(t, err)
	time.Sleep(time.Second / 5)
	err = wsA.ReadJSON(&m)
	require.Nil(t, err)
	require.Contains(t, m, "peer_update")
	var a AnswerMessage
	err = wsA.ReadJSON(&a)
	require.Equal(t, "B's answer", a.Answer)
	lA, err := strconv.ParseInt(redisDouble.HGet("peer:A", "last_connect"), 10, 64)
	require.Nil(t, err)
	lB, err := strconv.ParseInt(redisDouble.HGet("peer:B", "last_connect"), 10, 64)
	require.Nil(t, err)
	require.LessOrEqual(t, startTime, lA)
	require.LessOrEqual(t, startTime, lB)
}
func TestVerifyQR(t *testing.T) {
	startTest(t)
	token := "=a+valid/token="
	// setup the fixture - a user, his token and two peers
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("u:j", "email", "j@example.com")
	ok, err := getUserKey("j")
	require.Nil(t, err)
	redisDouble.Set(fmt.Sprintf("token:%s", token), "j")
	authU := fmt.Sprintf("http://127.0.0.1:17777/pb/%s", url.PathEscape(token))
	resp, err := http.Get(authU)
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
	doc, err := html.Parse(resp.Body)
	require.Nil(t, err)
	var f func(*html.Node)
	validImg := false
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			var val string
			var name string
			validAttrs := 0
			for _, a := range n.Attr {
				if a.Key == "value" {
					val = string(a.Val)
					validAttrs++
				} else if a.Key == "name" {
					name = string(a.Val)
					validAttrs++
				}
			}
			if name == "token" {
				token = val
				require.Equal(t, 2, validAttrs, "Bad input elmement attrs: %v", n.Attr)
			} else if name == "otp" {
				require.Equal(t, 1, validAttrs, "Bad input elmement attrs: %v", n.Attr)
			}
			return
		}
		if n.Type == html.ElementNode && n.Data == "img" {
			// ignore the header row
			// the first child is the input field for the checkbox
			count := 0
			for _, a := range n.Attr {
				if a.Key == "alt" {
					count += 1
					require.Equal(t, "QR code for otp", a.Val)
				} else if a.Key == "src" {
					count += 1
					require.Less(t, 100, len(a.Val))
				}
			}
			require.Equal(t, 2, count, "Bad img elmement")
			validImg = true
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	require.True(t, validImg, "Image elment is not valid")
	otp, err := totp.GenerateCode(ok.Secret(), time.Now())
	require.Nil(t, err)
	u := fmt.Sprintf("http://127.0.0.1:17777/qr/%s", token)
	respP, err := http.PostForm(u, url.Values{"otp": {otp}})
	require.Nil(t, err)
	require.Equal(t, 200, respP.StatusCode)
}
func TestGetUsersList(t *testing.T) {
	startTest(t)
	token := "=a+valid/token="
	// setup the fixture - a user, his token and two peers
	redisDouble.HSet("u:j", "email", "j@example.com", "secert", "AVERYSECRETTOKEN", "QRVerified", "1")
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.Set(fmt.Sprintf("token:%s", token), "j")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "zulu",
		"user", "j", "verified", "0")
	redisDouble.HSet("peer:B", "fp", "B", "name", "bar", "kind", "alpha",
		"user", "j", "verified", "1")
	// setup a mock revenuecat server
	server := httptest.NewServer(http.HandlerFunc(rcHandler))
	defer server.Close()
	os.Setenv("REVENUECAT_URL", server.URL)
	ws, _, err := openWS("ws://127.0.0.1:17777/ws?fp=B&name=bar&uid=j&kind=lay")
	require.Nil(t, err)
	defer ws.Close()
	authU := fmt.Sprintf("http://127.0.0.1:17777/pb/%s", url.PathEscape(token))
	time.Sleep(time.Second / 100)
	resp, err := http.Get(authU)
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
	doc, err := html.Parse(resp.Body)
	require.Nil(t, err)
	var crawl func(*testing.T, *html.Node)
	row := 0
	col := 0
	namesVerified := 0
	crawl = func(t *testing.T, n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "tr":
				col = 0
				row++
			case "td":
				switch col {
				case 1:
					if row == 2 {
						require.Equal(t, "foo", n.FirstChild.Data)
					} else if row == 3 {
						require.Equal(t, "bar", n.FirstChild.Data)
					} else {
						t.Fail()
					}
					namesVerified++
				}
				col++
			case "input":
				var (
					typ     string
					name    string
					checked bool
				)
				for _, a := range n.Attr {
					switch a.Key {
					case "name":
						name = a.Val
					case "type":
						typ = a.Val
					case "checked":
						checked = true
						require.Equal(t, 3, row, "Only the third row should be checked")
					}
				}
				if typ == "checkbox" && name != "rmrf" {
					if row == 2 {
						if col == 1 {
							require.Equal(t, "A", name)
						} else {
							require.Equal(t, "del-A", name)
						}
						require.False(t, checked)
					} else if row == 3 {
						if col == 1 {
							require.Equal(t, "B", name)
							require.True(t, checked)
						} else {
							require.Equal(t, "del-B", name)
						}
					} else {
						t.Fail()
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			crawl(t, c)
		}
	}
	crawl(t, doc)
	require.Equal(t, 2, namesVerified, "Should have validated two table rows' names")
}
func TestHTTPPeerVerification(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token, otp secret and two peers
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.Set("token:avalidtoken", "j")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "1", "online", "0")
	redisDouble.HSet("peer:B", "fp", "B", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0", "online", "0")
	ok, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Peerbbook",
		AccountName: "j",
	})
	require.Nil(t, err)
	otp, err := totp.GenerateCode(ok.Secret(), time.Now())
	require.Nil(t, err)
	redisDouble.HSet("u:j", "email", "j@example.com", "secret", ok.Secret(), "QRVerified", "1")
	// setup a mock revenuecat server
	server := httptest.NewServer(http.HandlerFunc(rcHandler))
	defer server.Close()
	os.Setenv("REVENUECAT_URL", server.URL)
	// connect using websockets
	ws, _, err := openWS("ws://127.0.0.1:17777/ws?fp=B&name=bar&uid=j")
	require.Nil(t, err)
	defer ws.Close()
	if err = ws.SetReadDeadline(time.Now().Add(ReadTimeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var s StatusMessage
	err = ws.ReadJSON(&s)
	require.Nil(t, err)
	require.Equal(t, http.StatusUnauthorized, s.Code)
	resp, err := http.PostForm("http://127.0.0.1:17777/pb/avalidtoken",
		url.Values{"B": {"checked"},
			"otp": {otp},
		})
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)
	time.Sleep(time.Second / 100)
	require.Equal(t, "0", redisDouble.HGet("peer:A", "verified"))
	require.Equal(t, "1", redisDouble.HGet("peer:B", "verified"))
	var m map[string]interface{}
	err = ws.ReadJSON(&m)
	require.Nil(t, err)
	require.Contains(t, m, "code", "got msg %v", m)
	require.Equal(t, float64(200), m["code"], "got msg %v", m)
	err = ws.ReadJSON(&m)
	require.Contains(t, m, "peers", "got msg %v", m)
	require.Contains(t, m, "uid")
	peers := m["peers"].([]interface{})
	require.Equal(t, 2, len(peers), "got msg %v", m)
	require.Nil(t, err)
}
func TestVerifyUnverified(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token and two peers
	redisDouble.HSet("u:j", "email", "j@example.com")
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0")
	redisDouble.HSet("peer:B", "fp", "B", "name", "bar", "kind", "lay",
		"user", "j", "verified", "1")
	msg := map[string]string{"fp": "A", "uid": "j"}
	m, err := json.Marshal(msg)
	require.Nil(t, err)
	resp, err := http.Post("http://127.0.0.1:17777/verify", "application/json",
		bytes.NewBuffer(m))
	require.Nil(t, err)
	defer resp.Body.Close()
	var ret map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&ret)
	require.Nil(t, err)
	require.False(t, ret["verified"].(bool))
}
func TestWSNew(t *testing.T) {
	startTest(t)
	// setup a mock revenuecat server
	server := httptest.NewServer(http.HandlerFunc(rcHandler))
	defer server.Close()
	os.Setenv("REVENUECAT_URL", server.URL)
	// setup the fixture - a user, his token and two peers
	ws, _, err := openWS("ws://127.0.0.1:17777/ws?fp=Z&name=foo&uid=j&kind=server")
	var m map[string]interface{}
	err = ws.ReadJSON(&m)
	require.Nil(t, err)
	require.Contains(t, m, "code", "got msg %v", m)
	require.Equal(t, float64(401), m["code"], "got msg %v", m)
	time.Sleep(time.Second)
	require.Equal(t, "0", redisDouble.HGet("peer:Z", "verified"))
	require.Equal(t, "foo", redisDouble.HGet("peer:Z", "name"))
	require.Equal(t, "server", redisDouble.HGet("peer:Z", "kind"))
	require.Equal(t, "j", redisDouble.HGet("peer:Z", "user"))
	if err = ws.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	err2 := ws.ReadJSON(&m).(net.Error)
	require.NotNil(t, err2)
	require.True(t, err2.Timeout())
}
func TestVerifyNew(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token and two peers
	msg := map[string]string{"fp": "A", "uid": "j", "kind": "server",
		"name": "foo"}
	m, err := json.Marshal(msg)
	require.Nil(t, err)
	resp, err := http.Post("http://127.0.0.1:17777/verify", "application/json",
		bytes.NewBuffer(m))
	require.Nil(t, err)
	require.Equal(t, 201, resp.StatusCode)
	defer resp.Body.Close()
	var ret map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&ret)
	require.Nil(t, err)
	require.False(t, ret["verified"].(bool))
	require.Equal(t, "0", redisDouble.HGet("peer:A", "verified"))
	require.Equal(t, "foo", redisDouble.HGet("peer:A", "name"))
	require.Equal(t, "server", redisDouble.HGet("peer:A", "kind"))
}
func TestVerifyAVerified(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token and two peers
	redisDouble.SetAdd("user:j", "B")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0")
	redisDouble.HSet("peer:B", "fp", "B", "name", "bar", "kind", "lay",
		"user", "j", "verified", "1")
	msg := map[string]string{"fp": "B", "uid": "j"}
	m, err := json.Marshal(msg)
	require.Nil(t, err)
	resp, err := http.Post("http://127.0.0.1:17777/verify", "application/json",
		bytes.NewBuffer(m))
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)
	var ret map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&ret)
	require.Nil(t, err, "failed to decode: %v", ret)
	v, found := ret["verified"]
	require.True(t, found, "got back: %v", ret)
	verified := v.(bool)
	require.True(t, verified, "got back: %v", ret)
}
func TestVerifyWrongUser(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token and two peers
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0")
	redisDouble.HSet("peer:B", "fp", "B", "name", "bar", "kind", "lay",
		"user", "j", "verified", "1")

	msg := map[string]string{"fp": "B", "uid": "i"}
	m, err := json.Marshal(msg)
	require.Nil(t, err)
	resp, err := http.Post("http://127.0.0.1:17777/verify", "application/json",
		bytes.NewBuffer(m))
	require.Nil(t, err, err)
	require.Equal(t, 409, resp.StatusCode)
}

// TestValidatePeerNPublish runs the following scenarion
func TestValidatePeerNPublish(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token and two peers
	redisDouble.Set("token:avalidtoken", "j")
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0", "online", "0")
	redisDouble.HSet("peer:B", "fp", "B", "name", "bar", "kind", "lay",
		"user", "j", "verified", "1", "online", "0")
	ok, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Peerbbook",
		AccountName: "j",
	})
	require.Nil(t, err)
	otp, err := totp.GenerateCode(ok.Secret(), time.Now())
	require.Nil(t, err)
	redisDouble.HSet("u:j", "email", "j@example.com", "secret", ok.Secret(), "QRVerified", "1")
	// setup a mock revenuecat server
	server := httptest.NewServer(http.HandlerFunc(rcHandler))
	defer server.Close()
	os.Setenv("REVENUECAT_URL", server.URL)
	// connect both peers using websockets
	wsA, _, err := openWS("ws://127.0.0.1:17777/ws?fp=A&name=foo&kind=lay&uid=j")
	require.Nil(t, err)
	defer wsA.Close()
	if err = wsA.SetReadDeadline(time.Now().Add(ReadTimeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	wsB, _, err := openWS("ws://127.0.0.1:17777/ws?fp=B&name=bar&kind=lay&uid=j")
	require.Nil(t, err)
	defer wsB.Close()
	if err = wsB.SetReadDeadline(time.Now().Add(ReadTimeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	// get the unautherized message on A
	var s StatusMessage
	err = wsA.ReadJSON(&s)
	require.Nil(t, err)
	require.Equal(t, 401, s.Code)
	// TODO: use this is the code as well
	var pl struct {
		Peers *PeerList `json:"peers"`
		UID   string    `json:"uid"`
	}
	// get the peers list on B
	time.Sleep(time.Second / 10)
	err = wsB.ReadJSON(&pl)
	require.Nil(t, err)
	require.Equal(t, "j", pl.UID)
	require.Equal(t, 2, len(*pl.Peers))
	// authenticate both A & B
	resp, err := http.PostForm("http://127.0.0.1:17777/pb/avalidtoken",
		url.Values{"A": {"checked"}, "B": {"checked"}, "otp": {otp}})
	require.Nil(t, err)
	// test if A was authenticated - both in redis and a message sent over ws
	require.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
	time.Sleep(time.Second / 100)
	require.Equal(t, "1", redisDouble.HGet("peer:A", "verified"))
	var s2 StatusMessage
	err = wsA.ReadJSON(&s2)
	require.Nil(t, err)
	require.Equal(t, 200, s2.Code, "go msg: %s", s.Text)
	err = wsA.ReadJSON(&pl)
	require.Nil(t, err, "ReadJSON returned err: %s", err)
	require.NotNil(t, pl.Peers)
	require.NotEmpty(t, pl.UID)
}
func TestGoodOTP2(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token and two peers
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.Set("token:avalidtoken", "j")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "1", "online", "0")
	redisDouble.HSet("peer:B", "fp", "B", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0", "online", "0")
	ok, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Peerbbook",
		AccountName: "j",
	})
	require.Nil(t, err)
	rc := db.pool.Get()
	defer rc.Close()
	otp, err := totp.GenerateCode(ok.Secret(), time.Now())
	require.Nil(t, err)
	redisDouble.HSet("u:j", "secret", ok.Secret(), "QRVerified", "1")
	resp, err := http.PostForm("http://127.0.0.1:17777/pb/avalidtoken",
		url.Values{"rmrf": {"checked"}, "otp": {otp}})
	require.Nil(t, err)
	defer resp.Body.Close()
	bb, err := io.ReadAll(resp.Body)
	bs := string(bb)
	require.Equal(t, 200, resp.StatusCode, bs)
	require.False(t, redisDouble.Exists("peer:A"))
	require.False(t, redisDouble.Exists("peer:B"))
	require.False(t, redisDouble.Exists("user:j"))
}
func TestMiniRedis(t *testing.T) {
	startTest(t)
	conn := db.pool.Get()
	defer conn.Close()
	_, err := conn.Do("SET", "peer:A", "1")
	require.Nil(t, err)

	require.True(t, redisDouble.Exists("peer:A"))
}
func TestRemoveAll(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token and two peers
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("u:j", "email", "j@example.com", "QRVerified", "1")
	redisDouble.Set("token:avalidtoken", "j")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0")
	ok, err := getUserKey("j")
	require.Nil(t, err)
	otp, err := totp.GenerateCode(ok.Secret(), time.Now())
	require.Nil(t, err)
	resp, err := http.PostForm("http://127.0.0.1:17777/pb/avalidtoken",
		url.Values{"rmrf": {"checked"},
			"otp": {otp}})
	require.Nil(t, err)
	defer resp.Body.Close()
	bb, err := io.ReadAll(resp.Body)
	bs := string(bb)
	require.Equal(t, 200, resp.StatusCode, bs)
	time.Sleep(time.Second / 100)
	require.False(t, redisDouble.Exists("peer:A"))
	require.False(t, redisDouble.Exists("peer:B"))
	require.False(t, redisDouble.Exists("user:j"))
}
func TestBadOTP(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token and two peers
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.Set("token:avalidtoken", "j")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0")
	ok, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Peerbbook",
		AccountName: "j",
	})
	require.Nil(t, err)
	redisDouble.HSet("u:j", "user", ok.Secret(), "QRVerified", "1")
	resp, err := http.PostForm("http://127.0.0.1:17777/pb/avalidtoken",
		url.Values{"rmrf": {"checked"}, "otp": {"98989898"}})
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)
	time.Sleep(time.Second / 100)
	// ensure nothing was removed
	require.True(t, redisDouble.Exists("peer:A"))
	require.True(t, redisDouble.Exists("peer:B"))
	require.True(t, redisDouble.Exists("user:j"))
	// TODO: ensure the OTP error message is the resp.Body
}
func TestGoodValidateOTP(t *testing.T) {
	startTest(t)
	token := "=b+valid/token="
	// setup the fixture - a user, his token and two peers
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("u:j", "email", "j@example.com")
	redisDouble.Set(fmt.Sprintf("token:%s", token), "j")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0", "online", "0")

	require.False(t, db.IsQRVerified("j"))
	ok, err := getUserKey("j")
	otp, err := totp.GenerateCode(ok.Secret(), time.Now())
	u := fmt.Sprintf("http://127.0.0.1:17777/qr/%s", token)
	resp, err := http.PostForm(u, url.Values{"otp": {otp}})
	require.Nil(t, err)
	defer resp.Body.Close()
	bb, err := io.ReadAll(resp.Body)
	bs := string(bb)
	require.Equal(t, 200, resp.StatusCode, "Status code %d, body: %s",
		resp.StatusCode, bs)
	require.True(t, db.IsQRVerified("j"))
}
func TestBadValidateOTP(t *testing.T) {
	startTest(t)
	token := "=b+valid/token="
	// setup the fixture - a user, his token and two peers
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("u:j", "email", "j@example.com")
	redisDouble.Set(fmt.Sprintf("token:%s", token), "j")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0", "online", "0")

	u := fmt.Sprintf("http://127.0.0.1:17777/qr/%s", token)
	resp, err := http.PostForm(u, url.Values{"otp": {"123456"}})
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
	bb, err := io.ReadAll(resp.Body)
	bs := string(bb)
	require.Contains(t, bs, "One Time Password validation failed")

}
func TestUserSecret(t *testing.T) {
	startTest(t)
	time.Sleep(time.Second / 100)
	s, err := db.getUserSecret("j")
	otp, err := totp.GenerateCode(s, time.Now())
	require.Nil(t, err)
	v := totp.Validate(otp, s)
	require.True(t, v)
}
func TestDisconnectReconnect(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token and two peers
	redisDouble.HSet("u:j", "email", "j@example.com")
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay",
		"user", "j", "verified", "1")
	// setup a mock revenuecat server
	server := httptest.NewServer(http.HandlerFunc(rcHandler))
	defer server.Close()
	os.Setenv("REVENUECAT_URL", server.URL)
	ws1, _, err := openWS("ws://127.0.0.1:17777/ws?fp=A&name=foo&kind=lay&uid=j")
	require.Nil(t, err)
	time.Sleep(time.Millisecond * 50)
	online := redisDouble.HGet("peer:A", "online")
	require.Equal(t, "1", online)
	ws1.Close()
	time.Sleep(time.Millisecond * 50)
	online = redisDouble.HGet("peer:A", "online")
	require.Equal(t, "0", online)
	ws2, _, err := openWS("ws://127.0.0.1:17777/ws?fp=A&name=foo&kind=lay&uid=j")
	require.Nil(t, err)
	time.Sleep(time.Millisecond * 50)
	online = redisDouble.HGet("peer:A", "online")
	require.Equal(t, "1", online)
	time.Sleep(pingPeriod + time.Millisecond*50)
	online = redisDouble.HGet("peer:A", "online")
	require.Equal(t, "1", online)
	ws2.Close()

}
func TestDeletePeerFromWeb(t *testing.T) {
	startTest(t)
	// setup the fixture - a user, his token and two peers
	redisDouble.SetAdd("user:j", "A", "B")
	redisDouble.HSet("u:j", "email", "j@example.com", "QRVerified", "1")
	redisDouble.HSet("peer:A", "fp", "A", "name", "foo", "kind", "lay")
	redisDouble.HSet("peer:A", "user", "j", "verified", "1")
	redisDouble.HSet("peer:B", "fp", "B", "name", "foo", "kind", "lay",
		"user", "j", "verified", "0")
	redisDouble.Set("token:avalidtoken", "j")
	// get the OTP
	ok, err := getUserKey("j")
	require.Nil(t, err)
	otp, err := totp.GenerateCode(ok.Secret(), time.Now())
	require.Nil(t, err)
	resp, err := http.PostForm("http://127.0.0.1:17777/pb/avalidtoken",
		url.Values{"del-A": {"checked"}, "otp": {otp}})
	// validate 200 response
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	defer resp.Body.Close()
	// validate the peer is gone
	require.False(t, redisDouble.Exists("peer:A"))
	require.True(t, redisDouble.Exists("peer:B"))
}
func TestWebexec(t *testing.T) {
	startTest(t)
	done := make(chan bool)
	// start the webrtc client
	client, cert, err := newClient(t)
	require.NoError(t, err, "Failed to create a client: %q", err)
	cdc, err := client.CreateDataChannel("%", nil)
	require.Nil(t, err, "Failed to create the control data channel: %q", err)
	clientOffer, err := client.CreateOffer(nil)
	require.Nil(t, err, "Failed to create client offer: %q", err)
	gatherComplete := webrtc.GatheringCompletePromise(client)
	err = client.SetLocalDescription(clientOffer)
	require.Nil(t, err, "Failed to set client's local Description client offer: %q", err)
	select {
	case <-time.After(3 * time.Second):
		t.Errorf("timed out waiting to ice gathering to complete")
	case <-gatherComplete:
		buf := make([]byte, 4096)
		l, err := peers.EncodeOffer(buf, *client.LocalDescription())
		require.Nil(t, err, "Failed ending an offer: %v", clientOffer)
		fp, err := peers.ExtractFP(cert)
		require.NoError(t, err, "Failed to extract the fingerprint: %q", err)
		p := httpserver.ConnectRequest{fp, 1, string(buf[:l])}
		m, err := json.Marshal(p)
		resp, err := http.Post("http://127.0.0.1:17777/we", "application/json", bytes.NewBuffer(m))
		require.NoError(t, err, "Failed to connect to the server")
		defer resp.Body.Close()
		answer, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "Failed to read the offer")
		require.Equal(t, http.StatusOK, resp.StatusCode, "Failed to connect to the server", string(answer))
		// decode the answer from the answer
		var sd webrtc.SessionDescription
		err = peers.DecodeOffer(&sd, answer)
		require.Nil(t, err, "Failed decoding an offer: %v", clientOffer)
		client.SetRemoteDescription(sd)
		// when cdc is open, we're done
		cdc.OnOpen(func() {
			done <- true
		})
	}
	select {
	case <-time.After(3 * time.Second):
		t.Errorf("Timeouton cdc open")
	case <-done:
	}
	/*
			// There's t.Cleanup in go 1.15+
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err := Shutdown(ctx)
			require.Nil(t, err, "Failed shutting the http server: %v", err)
		Shutdown()
		// TODO: be smarter, this is just a hack to get github action to pass
		time.Sleep(500 * time.Millisecond)
	*/
}
