package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTooManyPeers(t *testing.T) {
	startTest(t)
	for i := 0; i < MaxPeersPerUser; i++ {
		p := Peer{
			FP:   fmt.Sprintf("%2d", i+1),
			User: "j",
			Kind: "foo",
			Name: fmt.Sprintf("p%03d", i),
		}
		err := db.AddPeer(&p)
		require.Nil(t, err)
	}
	p := Peer{
		FP:   "9999",
		User: "j",
		Kind: "foo"}
	err := db.AddPeer(&p)
	require.NotNil(t, err)
}
