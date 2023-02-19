package main

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestSetPublicKey(t *testing.T) {
	// generate a an rsa if publick, private key strings based
	// on ed25519
	Logger = zaptest.NewLogger(t).Sugar()
	pubKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEheO5ZE+Xy0EXZeUglDOG+Bqr2WgNvjl23dwIdMjVzy foo@bar"
	_, err := miniredis.Run()
	require.NoError(t, err)
	peer := NewPeer("A", "foo", "j", "client", pubKey)
	c, err := NewConn(peer)
	require.NoError(t, err)
	require.NotNil(t, c)
}
