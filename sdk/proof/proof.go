// Package proof signs and verifies the per-request proof of possession.
//
// A proof is a compact JWS signed with the agent's Ed25519 key, modeled on
// DPoP (RFC 9449) but not compliant with it. Its header carries the agent's
// public key. Its claims bind it to one request: the method, the URL, a hash
// of the body and, when the request carries an access token, a hash of the
// token. A stolen access token is useless without a proof, and a captured
// proof is useless for any other request.
//
// This package holds the protocol logic and nothing else: no network, no
// storage. The replay check (spec D16) needs a store and so is not here. The
// verifier's orchestration (key set cache, proof mode, the access token
// checks) is the caller's.
package proof

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/atomityhq/atomity-k8s-agent/sdk/internal/b64"
	"github.com/atomityhq/atomity-k8s-agent/sdk/internal/jws"
	"github.com/atomityhq/atomity-k8s-agent/sdk/jwk"
	"github.com/atomityhq/atomity-k8s-agent/sdk/protocol"
)

// Claims are the claims of a proof.
type Claims struct {
	// HTM is the HTTP method, uppercase.
	HTM string `json:"htm"`
	// HTU is the request URL without query or fragment.
	HTU string `json:"htu"`
	// IAT is when the agent signed the proof, in seconds since the epoch.
	IAT int64 `json:"iat"`
	// JTI is at least 128 random bits, base64url, unique per proof.
	JTI string `json:"jti"`
	// ATH is the base64url SHA-256 of the access token string. Empty on calls
	// that carry no token.
	ATH string `json:"ath,omitempty"`
	// BSH is the base64url SHA-256 of the exact request body bytes.
	BSH string `json:"bsh"`
}

type header struct {
	Alg string     `json:"alg"`
	Typ string     `json:"typ"`
	JWK jwk.Public `json:"jwk"`
}

// BodyHash is the base64url SHA-256 of body. A request with no body hashes
// the empty string.
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return b64.Encode(sum[:])
}

// TokenHash is the base64url SHA-256 of an access token string, as carried in
// the `ath` claim.
func TokenHash(token string) string { return BodyHash([]byte(token)) }

// HTU returns raw as a proof's htu: the URL without its query and fragment.
// The URL must be absolute and must not carry credentials. Both sides take the
// configured public URL, never the Host header, so they agree on the text.
func HTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("proof: the URL does not parse")
	}
	if u.Scheme == "" || u.Host == "" {
		return "", errors.New("proof: the URL must be absolute")
	}
	if u.User != nil {
		return "", errors.New("proof: the URL must not carry credentials")
	}
	u.RawQuery, u.ForceQuery = "", false
	u.Fragment, u.RawFragment = "", ""
	return u.String(), nil
}

// SignInput is everything a proof binds.
type SignInput struct {
	// Key is the agent's private key.
	Key ed25519.PrivateKey
	// Method is the HTTP method of the request.
	Method string
	// URL is the configured public URL the request goes to.
	URL string
	// Body is the exact request body bytes, empty if there is none.
	Body []byte
	// Token is the access token sent with the request. Empty on control plane
	// calls that carry none (Enroll, GetToken).
	Token string
	// Now is the time to sign into iat. An agent passes its offset-corrected
	// clock here (see package clock).
	Now time.Time
	// Rand supplies the jti. Nil means crypto/rand. Injectable for tests.
	Rand io.Reader
}

// Sign returns a proof for one request.
func Sign(in SignInput) (string, error) {
	if len(in.Key) != ed25519.PrivateKeySize {
		return "", errors.New("proof: not an Ed25519 private key")
	}
	if in.Method == "" {
		return "", errors.New("proof: the method is empty")
	}
	if in.Now.IsZero() {
		return "", errors.New("proof: the time is not set")
	}
	htu, err := HTU(in.URL)
	if err != nil {
		return "", err
	}
	r := in.Rand
	if r == nil {
		r = rand.Reader
	}
	jti := make([]byte, protocol.JTIMinBytes)
	if _, err := io.ReadFull(r, jti); err != nil {
		return "", fmt.Errorf("proof: reading entropy for the jti: %w", err)
	}

	claims := Claims{
		HTM: strings.ToUpper(in.Method),
		HTU: htu,
		IAT: in.Now.Unix(),
		JTI: b64.Encode(jti),
		BSH: BodyHash(in.Body),
	}
	if in.Token != "" {
		claims.ATH = TokenHash(in.Token)
	}
	hdr := header{
		Alg: protocol.Algorithm,
		Typ: protocol.ProofType,
		JWK: jwk.FromPublicKey(in.Key.Public().(ed25519.PublicKey)),
	}
	return jws.Sign(in.Key, hdr, claims)
}

// Expected is what a verifier knows about the request in front of it.
type Expected struct {
	// Method and URL are the request's method and the configured public URL.
	Method string
	URL    string
	// Body is the exact request body bytes.
	Body []byte
	// Token is the access token string sent with the request, or empty if the
	// call carries none. A proof for a token-less call must not carry ath, and
	// one for a call with a token must.
	Token string
	// Now is the verifier's time, from an injected clock.
	Now time.Time
	// Window is how far iat may be from Now on either side. Zero means
	// protocol.ProofWindow.
	Window time.Duration
	// BoundThumbprint is the thumbprint the access token is bound to (its
	// cnf.jkt). If set, the proof's key must match it. Leave it empty on calls
	// that carry no token.
	BoundThumbprint string
}

// Verified is a proof that passed every check this package can make.
type Verified struct {
	// Key is the agent's public key from the proof's header.
	Key jwk.Public
	// Thumbprint is the thumbprint of that key.
	Thumbprint string
	Claims     Claims
}

// Verify checks a proof against the request, in the order of the spec's
// verification algorithm (steps 6 to 9), and stops at the first failure.
//
// Every failure is a *protocol.Error. The reasons are:
//   - proof_invalid: the proof is not a well-formed proof, its header is not
//     exactly what the protocol defines, its key is not a public Ed25519 key,
//     its signature does not verify, or a claim is missing or malformed.
//   - proof_key_mismatch: the key is not the one BoundThumbprint names.
//   - proof_binding_mismatch: htm, htu, ath or bsh does not match the request.
//   - proof_stale: iat is outside the window. The error carries the
//     verifier's time.
//
// Verify does not check for a replay, and does not check the access token.
func Verify(compact string, exp Expected) (*Verified, error) {
	if exp.Method == "" {
		return nil, errors.New("proof: Expected.Method is empty")
	}
	if exp.Now.IsZero() {
		return nil, errors.New("proof: Expected.Now is not set")
	}
	expectedHTU, err := HTU(exp.URL)
	if err != nil {
		return nil, fmt.Errorf("proof: Expected.URL: %w", err)
	}
	window := exp.Window
	if window == 0 {
		window = protocol.ProofWindow
	}

	invalid := func(detail string) error { return protocol.Fail(protocol.ReasonProofInvalid, detail) }

	// Step 6: the header.
	c, err := jws.Parse(compact)
	if err != nil {
		return nil, invalid("the proof is not a compact JWS")
	}
	h, err := jws.Object(c.Header)
	if err != nil {
		return nil, invalid("the header is not a JSON object")
	}
	if err := jws.OnlyMembers(h, "alg", "typ", "jwk"); err != nil {
		return nil, invalid("the header has a member the protocol does not define")
	}
	if alg, err := jws.String(h, "alg"); err != nil || alg != protocol.Algorithm {
		return nil, invalid("the algorithm is not EdDSA")
	}
	if typ, err := jws.String(h, "typ"); err != nil || typ != protocol.ProofType {
		return nil, invalid("the type is not agent-proof+jwt")
	}
	rawKey, ok := h["jwk"]
	if !ok {
		return nil, invalid("the header has no key")
	}
	key, err := jwk.Parse(rawKey)
	if err != nil {
		return nil, invalid("the key is not a public Ed25519 key")
	}
	pub, err := key.PublicKey()
	if err != nil {
		return nil, invalid("the key is not a public Ed25519 key")
	}
	thumbprint := jwk.ThumbprintOf(pub)

	// Step 7: the key is the one the access token is bound to.
	if exp.BoundThumbprint != "" && !jwk.EqualThumbprints(thumbprint, exp.BoundThumbprint) {
		return nil, protocol.Fail(protocol.ReasonProofKeyMismatch, "the key is not the one the token is bound to")
	}

	// Step 8: the signature.
	if !c.Verify(pub) {
		return nil, invalid("the signature does not verify")
	}

	// Step 9: the claims. The signature holds, so the claims are the agent's.
	claims, err := parseClaims(c.Payload)
	if err != nil {
		return nil, invalid(err.Error())
	}
	bind := func(detail string) error { return protocol.Fail(protocol.ReasonProofBindingMismatch, detail) }

	if claims.HTM != strings.ToUpper(exp.Method) {
		return nil, bind("the method does not match")
	}
	if claims.HTU != expectedHTU {
		return nil, bind("the URL does not match")
	}
	if delta := exp.Now.Sub(time.Unix(claims.IAT, 0)); delta < -window || delta > window {
		return nil, &protocol.Error{
			Reason:     protocol.ReasonProofStale,
			Detail:     "the proof is outside the allowed time window",
			ServerTime: exp.Now,
		}
	}
	if exp.Token == "" {
		if claims.ATH != "" {
			return nil, bind("the proof names a token but the request carries none")
		}
	} else if !equalHashes(claims.ATH, TokenHash(exp.Token)) {
		return nil, bind("the token hash does not match")
	}
	if !equalHashes(claims.BSH, BodyHash(exp.Body)) {
		return nil, bind("the body hash does not match")
	}

	return &Verified{Key: key, Thumbprint: thumbprint, Claims: claims}, nil
}

// parseClaims reads the claims and requires every one the protocol defines.
// ath is the exception: it is absent on calls that carry no token. Extra
// members are ignored.
func parseClaims(payload []byte) (Claims, error) {
	m, err := jws.Object(payload)
	if err != nil {
		return Claims{}, errors.New("the claims are not a JSON object")
	}
	var c Claims
	for name, dst := range map[string]*string{"htm": &c.HTM, "htu": &c.HTU, "jti": &c.JTI, "bsh": &c.BSH} {
		if *dst, err = jws.String(m, name); err != nil {
			return Claims{}, fmt.Errorf("claim %s is missing or not a string", name)
		}
	}
	if c.IAT, err = jws.Int64(m, "iat"); err != nil {
		return Claims{}, errors.New("claim iat is missing or not an integer")
	}
	if _, present := m["ath"]; present {
		if c.ATH, err = jws.String(m, "ath"); err != nil || c.ATH == "" {
			return Claims{}, errors.New("claim ath is not a non-empty string")
		}
	}
	// 128 random bits: the jti is what the replay check keys on.
	if raw, err := b64.Decode(c.JTI); err != nil || len(raw) < protocol.JTIMinBytes {
		return Claims{}, errors.New("claim jti is not at least 128 bits of base64url")
	}
	return c, nil
}

func equalHashes(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
