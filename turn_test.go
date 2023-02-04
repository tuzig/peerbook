package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGetCredentialsPost(t *testing.T) {
	t.Skip("Turn server stil WIP")
	startTest(t)
	redisDouble.HSet("iceserver:foo",
		"url", "turn:example.com",
		"username", "foo",
		"active", "1",
	)
	redisDouble.HSet("iceserver:bar",
		"url", "turn:anotherexample.com",
		"username", "foo",
		"active", "0",
	)
	resp, err := http.Post("http://127.0.0.1:17777/iceservers", "", nil)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)
	var servers []ICEServer
	err = json.NewDecoder(resp.Body).Decode(&servers)
	require.Nil(t, err)
	require.Equal(t, 1, len(servers))
	require.Equal(t, servers[0].Url, "turn:example.com")
	require.Equal(t, servers[0].Username, "foo")
	require.Equal(t, servers[0].Credential, "bar")
}
func TestTurn(t *testing.T) {
	// test the genCredentials function
	// the returned user name should be a combination of the username and the
	// timestamp
	// the returned credential should be the base64 encoded HMAC-SHA1 of the
	// compound username
	// the timestamp should be 24 hours after 1234567890
	// the secret key should be "thisisatest"
	// the username should be "foo"
	// the returned username should be "foo:1234654290"
	//
	now = func() time.Time { return time.Unix(1234567890, 0) }
	username, credential := genCredential("foo")
	// it should be 24 hours after 1234567890
	require.Equal(t, "foo:1234654290", username)
	decoded, err := base64.StdEncoding.DecodeString(credential)
	require.Nil(t, err)
	mac := hmac.New(sha1.New, []byte("thisisatest"))
	mac.Write([]byte("foo:1234654290"))
	expectedMAC := mac.Sum(nil)
	// the compound username should be "foo:1234654290"
	require.True(t, hmac.Equal(decoded, expectedMAC))
}
