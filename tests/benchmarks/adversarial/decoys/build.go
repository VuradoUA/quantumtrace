package main

import (
	"fmt"
	"hash/crc32"
)

const policyNote = "aes-128-ecb and RSA-1024 are banned by policy"

func sha1Sum(data []byte) uint32 { // named after the old helper; it is a CRC, not SHA-1
	return crc32.ChecksumIEEE(data)
}

func main() {
	fmt.Println(policyNote, sha1Sum([]byte("x")))
}
