// Package jwk is the agent's public key as the protocol carries it: an
// Ed25519 JSON Web Key (RFC 8037), and its thumbprint (RFC 7638).
package jwk

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/atomityhq/atomity-k8s-agent/sdk/internal/b64"
	"github.com/atomityhq/atomity-k8s-agent/sdk/internal/jws"
)

const (
	keyType = "OKP"
	curve   = "Ed25519"
)

// ErrPrivateMaterial is returned for a JWK that carries a private parameter.
// A public key sent to Atomity must never hold one.
var ErrPrivateMaterial = errors.New("jwk: key carries private material")

// Public is an Ed25519 public key in JWK form. It is an exchange format: the
// zero value is not a valid key, and Parse is how one is built from input.
type Public struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// Generate makes a new Ed25519 key pair. A nil reader means crypto/rand. The
// reader is injectable so tests can be deterministic.
func Generate(r io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if r == nil {
		r = rand.Reader
	}
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, nil, fmt.Errorf("jwk: generating key: %w", err)
	}
	return pub, priv, nil
}

// FromPublicKey returns the JWK of an Ed25519 public key.
func FromPublicKey(pub ed25519.PublicKey) Public {
	return Public{Kty: keyType, Crv: curve, X: b64.Encode(pub)}
}

// Parse reads a JWK from JSON and accepts nothing but a well-formed Ed25519
// public key: members kty, crv and x, and no others.
//
// A private parameter (d) gets ErrPrivateMaterial. Any other unknown member
// is refused as well, because a key format that is loose about members is one
// where two parties can read the same bytes differently.
func Parse(data []byte) (Public, error) {
	m, err := jws.Object(data)
	if err != nil {
		return Public{}, fmt.Errorf("jwk: %w", err)
	}
	if _, hasD := m["d"]; hasD {
		return Public{}, ErrPrivateMaterial
	}
	if err := jws.OnlyMembers(m, "kty", "crv", "x"); err != nil {
		return Public{}, errors.New("jwk: unexpected member")
	}
	var p Public
	for name, dst := range map[string]*string{"kty": &p.Kty, "crv": &p.Crv, "x": &p.X} {
		if *dst, err = jws.String(m, name); err != nil {
			return Public{}, fmt.Errorf("jwk: %w", err)
		}
	}
	if _, err := p.PublicKey(); err != nil {
		return Public{}, err
	}
	return p, nil
}

// UnmarshalJSON makes Public refuse anything Parse refuses, so decoding into a
// Public never yields an unchecked key.
func (p *Public) UnmarshalJSON(data []byte) error {
	parsed, err := Parse(data)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// PublicKey validates the JWK and returns the key.
func (p Public) PublicKey() (ed25519.PublicKey, error) {
	if p.Kty != keyType {
		return nil, errors.New("jwk: kty is not OKP")
	}
	if p.Crv != curve {
		return nil, errors.New("jwk: crv is not Ed25519")
	}
	x, err := b64.Decode(p.X)
	if err != nil {
		return nil, errors.New("jwk: x is not strict base64url")
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, errors.New("jwk: x is not 32 bytes")
	}
	return ed25519.PublicKey(x), nil
}

// Thumbprint is the RFC 7638 thumbprint: the SHA-256 of the canonical JSON of
// the key's required members, in alphabetical order with no whitespace, as
// base64url. For an Ed25519 key that JSON is
//
//	{"crv":"Ed25519","kty":"OKP","x":"<x>"}
//
// The key is decoded and encoded again first, so the thumbprint depends only
// on the key bytes, never on how the JWK happened to be written.
func (p Public) Thumbprint() (string, error) {
	pub, err := p.PublicKey()
	if err != nil {
		return "", err
	}
	return ThumbprintOf(pub), nil
}

// ThumbprintOf is the thumbprint of an Ed25519 public key. The key must be 32
// bytes.
func ThumbprintOf(pub ed25519.PublicKey) string {
	canonical := `{"crv":"` + curve + `","kty":"` + keyType + `","x":"` + b64.Encode(pub) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return b64.Encode(sum[:])
}

// MarshalCanonical returns the JWK as JSON in a fixed member order.
func (p Public) MarshalCanonical() ([]byte, error) {
	if _, err := p.PublicKey(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// EqualThumbprints compares two thumbprints in constant time.
func EqualThumbprints(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
