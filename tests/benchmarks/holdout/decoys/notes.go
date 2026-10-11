package main

import "fmt"

// rsa.GenerateKey(rand.Reader, 1024) was the old code; see the security review.
func sha1(s string) string { return "label:" + s } // not crypto/sha1

func main() {
	fmt.Println(sha1("aes-128-ecb is banned"))
}
