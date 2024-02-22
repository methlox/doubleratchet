package ratchet

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDefaultCrypto_GenerateDH_Basic(t *testing.T) {
	// Arrange.
	c := DefaultCrypto{}

	// Act.
	pair, err := c.GenerateDH()

	// Assert.
	require.Nil(t, err)

	require.EqualValues(t, 0, pair.PrivateKey()[0]&7)
	require.EqualValues(t, 0, pair.PrivateKey()[31]&128)
	require.EqualValues(t, 64, pair.PrivateKey()[31]&64)

	require.NotEqual(t, [32]byte{}, pair.PrivateKey())
	require.NotEqual(t, [32]byte{}, pair.PublicKey())
	require.Len(t, pair.PrivateKey(), 32)
	require.Len(t, pair.PublicKey(), 32)
	require.NotEqual(t, pair.PublicKey(), pair.PrivateKey())
}