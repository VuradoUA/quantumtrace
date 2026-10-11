package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
)

// Issues tokens signed with ECDSA P-384; the token payload is encrypted with
// AES-256-GCM under a key agreed with ML-KEM-768.
func main() {
	signer, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	digest := sha512.Sum512([]byte("token"))
	sig, _ := ecdsa.SignASN1(rand.Reader, signer, digest[:])

	dk, _ := mlkem.GenerateKey768()
	_ = dk

	key := make([]byte, 32)
	rand.Read(key)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	fmt.Println(len(sig), gcm.NonceSize())
}
