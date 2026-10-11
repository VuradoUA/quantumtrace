package main

import (
	"crypto/des"
	"crypto/ecdh"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 3072)
	wire, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, []byte("tunnel secret"), nil)
	peer, _ := ecdh.X25519().GenerateKey(rand.Reader)
	aead, _ := chacha20poly1305.New(make([]byte, chacha20poly1305.KeySize))
	legacy, _ := des.NewTripleDESCipher(make([]byte, 24))
	sum := md5.Sum(wire)
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	fmt.Println(peer, aead, legacy, sum, cfg)
}
