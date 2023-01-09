package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetTURNToken(t *testing.T) {
	t.Skip("Turn server stil WIP")
	token, err := getTURNToken()
	require.Nil(t, err)
	require.Equal(t, 1320, len(token))
}
func TestGetCredentialsPost(t *testing.T) {
	t.Skip("Turn server stil WIP")
	startTest(t)
	resp, err := http.Post("http://127.0.0.1:17777/turn", "", nil)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)
	var ret map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&ret)
	require.Nil(t, err)
	require.Nil(t, ret["ice_servers"])

}
