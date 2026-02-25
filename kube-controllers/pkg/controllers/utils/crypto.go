// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
)

var chars = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
var charLen = big.NewInt(int64(len(chars)))

// GeneratePassword generates a password using alphanumeric characters of a given length.
func GeneratePassword(length int) string {
	var b strings.Builder
	for b.Len() < length {
		idx, err := rand.Int(rand.Reader, charLen)
		if err != nil {
			panic(fmt.Errorf("failed to read crypto/rand data: %w", err))
		}
		b.WriteRune(chars[idx.Int64()])
	}
	return b.String()
}

// GenerateTruncatedHash Takes any interface and creates a hash. Length inputs larger than 64 or smaller are turned into 64.
func GenerateTruncatedHash(obj any, length int) (string, error) {
	if length < 0 || length > 64 {
		length = 64
	}
	h := sha256.New()
	_, err := fmt.Fprintf(h, "%q", obj)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:length], err
}
