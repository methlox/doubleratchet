package ratchet

import (
	"github.com/stretchr/testify/require"
	"testing"
)

var chainKey = Key{0xeb, 0x8, 0x10, 0x7c, 0x33, 0x54, 0x0, 0x20, 0xe9, 0x4f, 0x6c, 0x84, 0xe4, 0x39, 0x50, 0x5a, 0x2f, 0x60, 0xbe, 0x81, 0xa, 0x78, 0x8b, 0xeb, 0x1e, 0x2c, 0x9, 0x8d, 0x4b, 0x4d, 0xc1, 0x40}

func TestChain_Step(t *testing.T) {
	// Arrange.
	ch := kdfChain{
		Crypto: DefaultCrypto{},
		CK:     chainKey,
	}

	// Act.
	mk := ch.step()

	// Assert.
	require.EqualValues(t, 1, ch.N)
	require.NotEqual(t, chainKey, ch.CK)
	require.NotEqual(t, [32]byte{}, mk)
}

func TestRootChain_Step(t *testing.T) {
	// Arrange.
	rch := kdfRootChain{
		Crypto: DefaultCrypto{},
		CK:     chainKey,
	}

	// Act.
	ch, nhk := rch.step(Key{0xe3, 0xbe, 0xb9, 0x4e, 0x70, 0x17, 0x37, 0xc, 0x1, 0x8f, 0xa9, 0x7e, 0xef, 0x4, 0xfb, 0x23, 0xac, 0xea, 0x28, 0xf7, 0xa9, 0x56, 0xcc, 0x1d, 0x46, 0xf3, 0xb5, 0x1d, 0x7d, 0x7d, 0x5e, 0x2c})

	// Assert.
	require.NotEmpty(t, ch.Crypto)
	require.Empty(t, ch.N)
	require.NotEqual(t, [32]byte{}, ch)
	require.NotEqual(t, [32]byte{}, nhk)
}
