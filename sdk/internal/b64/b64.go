// Package b64 is base64url without padding, strictly.
//
// Go's base64 decoder skips carriage returns and line feeds and, unless
// told otherwise, accepts non-zero trailing bits. Either would let two
// different strings stand for the same bytes, which is exactly what a
// signature check and a thumbprint must not allow.
package b64

import (
	"encoding/base64"
	"errors"
	"strings"
)

var enc = base64.RawURLEncoding.Strict()

// Encode returns b as base64url without padding.
func Encode(b []byte) string { return enc.EncodeToString(b) }

// Decode accepts only what Encode produces: the URL alphabet, no padding, no
// line breaks, and zero trailing bits.
func Decode(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("b64: line break in input")
	}
	return enc.DecodeString(s)
}
