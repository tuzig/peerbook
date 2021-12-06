package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetTURNToken(t *testing.T) {

	token, err := getTURNToken()
	require.Nil(t, err)
	require.Equal(t, 1320, len(token))
}
func TestGetCredentialsPost(t *testing.T) {
	startTest(t)

	resp, err := http.Post("http://127.0.0.1:17777/turn", "", nil)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)
	var ret map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&ret)
	require.Nil(t, err)
	require.NotNil(t, ret["ice_servers"])
	require.Less(t, 3, len(ret["ice_servers"].([]interface{})))

}