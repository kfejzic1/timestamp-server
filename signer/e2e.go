package main

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// GenerateX25519KeyPair produces an ephemeral X25519 key pair for DKG E2E encryption.
func GenerateX25519KeyPair() (pubKey, privKey [32]byte) {
	if _, err := io.ReadFull(rand.Reader, privKey[:]); err != nil {
		panic(fmt.Sprintf("failed to generate X25519 private key: %v", err))
	}
	pub, err := curve25519.X25519(privKey[:], curve25519.Basepoint)
	if err != nil {
		panic(fmt.Sprintf("X25519 base point multiplication failed: %v", err))
	}
	copy(pubKey[:], pub)
	return pubKey, privKey
}

// SealBox encrypts plaintext for a recipient using NaCl box (X25519 + XSalsa20-Poly1305).
// Output: [24-byte nonce][ciphertext+auth_tag]
func SealBox(plaintext []byte, recipientPub, senderPriv [32]byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("nonce generation: %w", err)
	}

	sealed := box.Seal(nonce[:], plaintext, &nonce, &recipientPub, &senderPriv)
	return sealed, nil
}

// OpenBox decrypts data produced by SealBox.
func OpenBox(data []byte, senderPub, recipientPriv [32]byte) ([]byte, error) {
	if len(data) < 24+box.Overhead {
		return nil, fmt.Errorf("ciphertext too short")
	}

	var nonce [24]byte
	copy(nonce[:], data[:24])

	plaintext, ok := box.Open(nil, data[24:], &nonce, &senderPub, &recipientPriv)
	if !ok {
		return nil, fmt.Errorf("decryption failed (authentication error)")
	}

	return plaintext, nil
}
