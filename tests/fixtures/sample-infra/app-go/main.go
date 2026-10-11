package main

import (
	"crypto/ecdh"
	"crypto/rand"

	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	_ = priv
	aead, _ := chacha20poly1305.New(make([]byte, 32))
	_ = aead
}
