// Package jws is the little of JSON Web Signature the protocol uses: compact
// serialization, Ed25519 only.
//
// It is deliberately not a general JOSE library. It signs and parses exactly
// the shape protocol version 1 defines and nothing else.
package jws

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/atomityhq/atomity-k8s-agent/sdk/internal/b64"
)

// Compact is a parsed compact JWS. Parsing checks only the shape. Nothing in
// it is verified or trusted until Verify has been called.
type Compact struct {
	Header    []byte // decoded JSON
	Payload   []byte // decoded JSON
	Signature []byte

	signingInput string // the first two parts as sent: "header.payload"
}

// Parse splits a compact JWS into exactly three non-empty base64url parts.
func Parse(s string) (*Compact, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, errors.New("jws: not three dot-separated parts")
	}
	var raw [3][]byte
	for i, p := range parts {
		if p == "" {
			return nil, errors.New("jws: empty part")
		}
		b, err := b64.Decode(p)
		if err != nil {
			return nil, fmt.Errorf("jws: part %d is not base64url: %w", i+1, err)
		}
		raw[i] = b
	}
	return &Compact{
		Header:       raw[0],
		Payload:      raw[1],
		Signature:    raw[2],
		signingInput: parts[0] + "." + parts[1],
	}, nil
}

// Verify reports whether the signature is valid for the key. The signed
// bytes are the original text of the first two parts, not a re-encoding.
func (c *Compact) Verify(pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize || len(c.Signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, []byte(c.signingInput), c.Signature)
}

// Sign encodes header and claims as JSON, signs them and returns the compact
// JWS. Ed25519 signatures are deterministic, so equal inputs give equal output.
func Sign(priv ed25519.PrivateKey, header, claims any) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("jws: not an Ed25519 private key")
	}
	h, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("jws: encoding header: %w", err)
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jws: encoding claims: %w", err)
	}
	input := b64.Encode(h) + "." + b64.Encode(p)
	sig := ed25519.Sign(priv, []byte(input))
	return input + "." + b64.Encode(sig), nil
}

// Object decodes one JSON object into its members, left undecoded.
//
// Members are matched by their exact name. encoding/json would match a struct
// field case-insensitively, so {"ALG": ...} would pass for "alg", and nothing
// here may accept that. Anything after the object is an error.
func Object(data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var m map[string]json.RawMessage
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("jws: not a JSON object: %w", err)
	}
	if m == nil {
		return nil, errors.New("jws: JSON null is not an object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("jws: data after the JSON object")
	}
	return m, nil
}

// isNull reports whether raw is the JSON value null. encoding/json treats null
// as "leave the Go value alone", so decoding it into a string or an integer
// would quietly yield "" or 0 instead of an error.
func isNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

// String decodes a member that must be a JSON string. null is not a string.
func String(m map[string]json.RawMessage, name string) (string, error) {
	raw, ok := m[name]
	if !ok {
		return "", fmt.Errorf("jws: %q is missing", name)
	}
	if isNull(raw) {
		return "", fmt.Errorf("jws: %q is null", name)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("jws: %q is not a string", name)
	}
	return s, nil
}

// Int64 decodes a member that must be a JSON integer. null is not an integer.
func Int64(m map[string]json.RawMessage, name string) (int64, error) {
	raw, ok := m[name]
	if !ok {
		return 0, fmt.Errorf("jws: %q is missing", name)
	}
	if isNull(raw) {
		return 0, fmt.Errorf("jws: %q is null", name)
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, fmt.Errorf("jws: %q is not an integer", name)
	}
	return n, nil
}

// OnlyMembers returns an error if m has a member not in allowed.
func OnlyMembers(m map[string]json.RawMessage, allowed ...string) error {
	ok := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		ok[a] = true
	}
	for k := range m {
		if !ok[k] {
			return errors.New("jws: unexpected member in object")
		}
	}
	return nil
}
