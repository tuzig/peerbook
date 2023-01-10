package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetCredentialsPost(t *testing.T) {
	t.Skip("Turn server stil WIP")
	startTest(t)
	redisDouble.HSet("iceserver:foo",
		"urls", "turn:example.com",
		"username", "foo",
		"credential", "bar",
		"active", "1",
	)
	redisDouble.HSet("iceserver:bar",
		"urls", "turn:anotherexample.com",
		"username", "foo",
		"credential", "bar",
		"active", "0",
	)
	resp, err := http.Post("http://127.0.0.1:17777/turn", "", nil)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)
	var servers []ICEServer
	err = json.NewDecoder(resp.Body).Decode(&servers)
	require.Nil(t, err)
	require.Equal(t, 1, len(servers))
	require.Equal(t, servers[0].URL, "turn:example.com")
	require.Equal(t, servers[0].Username, "foo")
	require.Equal(t, servers[0].Credential, "bar")
}
