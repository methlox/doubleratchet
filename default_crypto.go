package ratchet

import (
	"crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

type dhPair struct {
	privateKey Key
	publicKey  Key
}

func (p dhPair) PrivateKey() Key {
	return p.privateKey
}

func (p dhPair) PublicKey() Key {
	return p.publicKey
}

func (p dhPair) String() string {
	return fmt.Sprintf("{privateKey: %s publicKey: %s}", p.privateKey, p.publicKey)
}

// DefaultCrypto is an implementation of Crypto with cryptographic primitives recommended
// by the Double Ratchet Algorithm specification. However, some details are different,
// see function comments for details.
type DefaultCrypto struct{}

// See the Crypto interface.
func (c DefaultCrypto) GenerateDH() (DHPair, error) {
	var privKey [32]byte
	if _, err := io.ReadFull(rand.Reader, privKey[:]); err != nil {
		return dhPair{}, fmt.Errorf("couldn't generate privKey: %s", err)
	}
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)
	return dhPair{
		privateKey: privKey,
		publicKey:  pubKey,
	}, nil
}

// See the Crypto interface.
func (c DefaultCrypto) DH(dhPair DHPair, dhPub Key) Key {
	var (
		dhOut   [32]byte
		privKey [32]byte = dhPair.PrivateKey()
		pubKey  [32]byte = dhPub
	)
	curve25519.ScalarMult(&dhOut, &privKey, &pubKey)
	return dhOut
}

func (c DefaultCrypto) KdfRK(rk, dhOut []byte) (rootKey, chainKey []byte) {
	// TODO: Implement.

	return nil, nil
}

func (c DefaultCrypto) KdfCK(ck []byte) ([]byte, []byte) {
	const (
		ckInput = 15
		mkInput = 16
	)

	// TODO: Use sha512? Think about how to switch the implementation later if not.
	hasher := hmac.New(sha256.New, ck)

	hasher.Write([]byte(ckInput))
	chainKey := hasher.Sum(nil)
	hasher.Reset()

	hasher.Write([]byte(mkInput))
	msgKey := hasher.Sum(nil)

	return chainKey, msgKey
}

func (c DefaultCrypto) Encrypt(mk, plaintext, associatedData []byte) (ciphertext []byte) {
	// TODO: Implement.

	return nil
}

func (c CryptoRecommended) Decrypt(mk, ciphertext, associatedData []byte) (plaintext []byte) {
	// TODO: Implement.

	return nil
}