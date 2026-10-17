package proof

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/atomityhq/atomity-k8s-agent/sdk/internal/b64"
	"github.com/atomityhq/atomity-k8s-agent/sdk/internal/jws"
	"github.com/atomityhq/atomity-k8s-agent/sdk/jwk"
	"github.com/atomityhq/atomity-k8s-agent/sdk/protocol"
)

var (
	now       = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	enrollURL = "https://cp.example.com/atomity.agent.v1.AgentFacingService/Enroll"
	body      = []byte("the request body")
)

func testKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func otherKey() ed25519.PrivateKey {
	_, priv, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{9}, 64)))
	return priv
}

func fixedRand() io.Reader { return bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)) }

func signInput() SignInput {
	_, priv := testKey()
	return SignInput{Key: priv, Method: "POST", URL: enrollURL, Body: body, Now: now, Rand: fixedRand()}
}

func expected() Expected {
	return Expected{Method: "POST", URL: enrollURL, Body: body, Now: now}
}

func mustSign(t *testing.T, in SignInput) string {
	t.Helper()
	p, err := Sign(in)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return p
}

func wantReason(t *testing.T, err error, want protocol.Reason) {
	t.Helper()
	var pe *protocol.Error
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v (%T), want a *protocol.Error with reason %s", err, err, want)
	}
	if pe.Reason != want {
		t.Fatalf("reason = %s (%s), want %s", pe.Reason, pe.Detail, want)
	}
}

// validParts returns the header and claims of a correct proof as maps, for a
// test to damage one member of and sign again.
func validParts() (header, claims map[string]any) {
	pub, _ := testKey()
	return map[string]any{
			"alg": "EdDSA",
			"typ": protocol.ProofType,
			"jwk": jwk.FromPublicKey(pub),
		}, map[string]any{
			"htm": "POST",
			"htu": enrollURL,
			"iat": now.Unix(),
			"jti": b64.Encode(bytes.Repeat([]byte{0x42}, 16)),
			"bsh": BodyHash(body),
		}
}

// craft signs arbitrary header and claims, which Sign refuses to produce.
func craft(t *testing.T, key ed25519.PrivateKey, edit func(h, c map[string]any)) string {
	t.Helper()
	h, c := validParts()
	if edit != nil {
		edit(h, c)
	}
	p, err := jws.Sign(key, h, c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// --- What a proof looks like ---

// The exact JSON a version 1 proof carries. A change here is a protocol
// version, so it must be a visible diff, not a silent one.
func TestSign_ProducesExactlyTheVersion1Shape(t *testing.T) {
	pub, _ := testKey()
	c, err := jws.Parse(mustSign(t, signInput()))
	if err != nil {
		t.Fatal(err)
	}
	wantHeader := `{"alg":"EdDSA","typ":"agent-proof+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + b64.Encode(pub) + `"}}`
	if string(c.Header) != wantHeader {
		t.Fatalf("header = %s\nwant     %s", c.Header, wantHeader)
	}
	wantClaims := fmt.Sprintf(`{"htm":"POST","htu":%q,"iat":%d,"jti":%q,"bsh":%q}`,
		enrollURL, now.Unix(), b64.Encode(bytes.Repeat([]byte{0x42}, 16)), BodyHash(body))
	if string(c.Payload) != wantClaims {
		t.Fatalf("claims = %s\nwant     %s", c.Payload, wantClaims)
	}
}

func TestSign_AddsAthOnlyWhenThereIsAToken(t *testing.T) {
	in := signInput()
	in.Token = "header.payload.signature"
	c, _ := jws.Parse(mustSign(t, in))
	if !strings.Contains(string(c.Payload), `"ath":"`+TokenHash(in.Token)+`"`) {
		t.Fatalf("no ath in %s", c.Payload)
	}

	c, _ = jws.Parse(mustSign(t, signInput()))
	if strings.Contains(string(c.Payload), `"ath"`) {
		t.Fatalf("ath present without a token: %s", c.Payload)
	}
}

// Ed25519 is deterministic and the jti reader is injected, so a fixed input
// gives one proof, byte for byte. This pins the whole encoding: header, claims,
// member order and signature. It is a regression check, not an independent one
// (the RFC 8037 tests are): if it fails, the wire format of protocol version 1
// changed, and that needs a new protocol version, not a new golden value.
func TestSign_IsDeterministicForFixedInputs(t *testing.T) {
	const golden = "eyJhbGciOiJFZERTQSIsInR5cCI6ImFnZW50LXByb29mK2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImViVldMb19tVlBsQWVMRVM2S21McDVBZmhUcm1sYjdYNE9PUkM2MEVsbVEifX0." +
		"eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9jcC5leGFtcGxlLmNvbS9hdG9taXR5LmFnZW50LnYxLkFnZW50RmFjaW5nU2VydmljZS9FbnJvbGwiLCJpYXQiOjE3OTE2MzM2MDAsImp0aSI6IlFrSkNRa0pDUWtKQ1FrSkNRa0pDUWciLCJic2giOiJhMTZzeUE4VE5vOEI0aEI1TmNhdHJNMVl6YU9uQ2N3dnJyNHB3QmFyaVdJIn0." +
		"zCu_UIo7WjqGCI_SNcR1swhdO8DWaBH22l9ffTeOv-IFLEG0dfHV38YTVBS8ozgI16HS342z0K1rAPrgxnsIAQ"

	if got := mustSign(t, signInput()); got != golden {
		t.Fatalf("the proof changed:\n got  %s\n want %s", got, golden)
	}
	// And the golden proof is itself a valid one.
	if _, err := Verify(golden, expected()); err != nil {
		t.Fatalf("the golden proof does not verify: %v", err)
	}
}

func TestSign_EveryProofHasItsOwnJTI(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		in := signInput()
		in.Rand = nil // crypto/rand
		c, _ := jws.Parse(mustSign(t, in))
		m, _ := jws.Object(c.Payload)
		jti, _ := jws.String(m, "jti")
		if raw, err := b64.Decode(jti); err != nil || len(raw) != protocol.JTIMinBytes {
			t.Fatalf("jti %q is not %d bytes", jti, protocol.JTIMinBytes)
		}
		if seen[jti] {
			t.Fatalf("jti repeated after %d proofs", i)
		}
		seen[jti] = true
	}
}

func TestSign_Refuses(t *testing.T) {
	_, priv := testKey()
	for name, mutate := range map[string]func(*SignInput){
		"no key":             func(in *SignInput) { in.Key = nil },
		"short key":          func(in *SignInput) { in.Key = priv[:10] },
		"no method":          func(in *SignInput) { in.Method = "" },
		"no time":            func(in *SignInput) { in.Now = time.Time{} },
		"relative URL":       func(in *SignInput) { in.URL = "/enroll" },
		"no host":            func(in *SignInput) { in.URL = "https:///enroll" },
		"URL with password":  func(in *SignInput) { in.URL = "https://user:pw@cp.example.com/x" },
		"garbage URL":        func(in *SignInput) { in.URL = "http://[::1" },
		"too little entropy": func(in *SignInput) { in.Rand = bytes.NewReader([]byte{1, 2}) },
	} {
		t.Run(name, func(t *testing.T) {
			in := signInput()
			mutate(&in)
			if p, err := Sign(in); err == nil {
				t.Fatalf("Sign accepted it and made %s", p)
			}
		})
	}
}

func TestSign_UppercasesTheMethod(t *testing.T) {
	in := signInput()
	in.Method = "post"
	c, _ := jws.Parse(mustSign(t, in))
	if !strings.Contains(string(c.Payload), `"htm":"POST"`) {
		t.Fatalf("method not uppercased: %s", c.Payload)
	}
	if _, err := Verify(mustSign(t, in), expected()); err != nil {
		t.Fatalf("a proof for post does not verify for POST: %v", err)
	}
}

func TestHTU(t *testing.T) {
	good := map[string]string{
		"https://cp.example.com/a/b":          "https://cp.example.com/a/b",
		"https://cp.example.com/a/b?x=1&y=2":  "https://cp.example.com/a/b",
		"https://cp.example.com/a/b#frag":     "https://cp.example.com/a/b",
		"https://cp.example.com/a/b?x=1#frag": "https://cp.example.com/a/b",
		"https://cp.example.com/a/b?":         "https://cp.example.com/a/b",
		"http://localhost:8080/enroll":        "http://localhost:8080/enroll",
		"https://cp.example.com":              "https://cp.example.com",
	}
	for in, want := range good {
		got, err := HTU(in)
		if err != nil || got != want {
			t.Errorf("HTU(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "cp.example.com/x", "/x", "https://", "https://u:p@h/x", "://x"} {
		if got, err := HTU(in); err == nil {
			t.Errorf("HTU(%q) = %q, want an error", in, got)
		}
	}
}

func TestBodyHash(t *testing.T) {
	// SHA-256 of the empty string, base64url (a request with no body).
	const empty = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
	if got := BodyHash(nil); got != empty {
		t.Fatalf("BodyHash(nil) = %s, want %s", got, empty)
	}
	if BodyHash([]byte{}) != empty {
		t.Fatal("an empty body and no body hash differently")
	}
	if BodyHash([]byte("a")) == BodyHash([]byte("b")) {
		t.Fatal("different bodies hash equal")
	}
	if TokenHash("abc") != BodyHash([]byte("abc")) {
		t.Fatal("TokenHash is not the hash of the token's bytes")
	}
}

// --- Verifying a good proof ---

func TestVerify_AcceptsAProofAndReturnsTheKey(t *testing.T) {
	pub, _ := testKey()
	v, err := Verify(mustSign(t, signInput()), expected())
	if err != nil {
		t.Fatal(err)
	}
	if v.Thumbprint != jwk.ThumbprintOf(pub) {
		t.Fatalf("thumbprint = %s", v.Thumbprint)
	}
	if got, _ := v.Key.PublicKey(); !got.Equal(pub) {
		t.Fatal("returned key is not the signer's")
	}
	if v.Claims.HTM != "POST" || v.Claims.HTU != enrollURL || v.Claims.IAT != now.Unix() ||
		v.Claims.BSH != BodyHash(body) || v.Claims.ATH != "" || v.Claims.JTI == "" {
		t.Fatalf("claims = %+v", v.Claims)
	}
}

func TestVerify_AcceptsAProofForARequestWithAToken(t *testing.T) {
	const token = "aaa.bbb.ccc"
	in := signInput()
	in.Token = token
	exp := expected()
	exp.Token = token
	if _, err := Verify(mustSign(t, in), exp); err != nil {
		t.Fatal(err)
	}
}

func TestVerify_IgnoresTheQueryAndFragmentOfTheExpectedURL(t *testing.T) {
	exp := expected()
	exp.URL = enrollURL + "?debug=1#x"
	if _, err := Verify(mustSign(t, signInput()), exp); err != nil {
		t.Fatalf("a query on the request URL broke verification: %v", err)
	}
}

func TestVerify_EmptyBodyAndNoBodyAreTheSame(t *testing.T) {
	in := signInput()
	in.Body = nil
	exp := expected()
	exp.Body = []byte{}
	if _, err := Verify(mustSign(t, in), exp); err != nil {
		t.Fatal(err)
	}
}

func TestVerify_RoundTripsManyRequests(t *testing.T) {
	_, priv := testKey()
	for i := 0; i < 200; i++ {
		method := []string{"POST", "PUT", "GET", "DELETE"}[i%4]
		url := fmt.Sprintf("https://gw%d.example.com/v1/path/%d", i, i)
		b := bytes.Repeat([]byte{byte(i)}, i)
		tok := ""
		if i%2 == 0 {
			tok = fmt.Sprintf("tok.%d.sig", i)
		}
		p, err := Sign(SignInput{Key: priv, Method: method, URL: url, Body: b, Token: tok, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(p, Expected{Method: method, URL: url, Body: b, Token: tok, Now: now}); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
}

// --- Step 6: the header ---

func TestVerify_Step6_TheProofMustBeWellFormed(t *testing.T) {
	pub, priv := testKey()

	cases := map[string]func(h, c map[string]any){
		"alg none":                func(h, c map[string]any) { h["alg"] = "none" },
		"alg HS256":               func(h, c map[string]any) { h["alg"] = "HS256" },
		"alg RS256":               func(h, c map[string]any) { h["alg"] = "RS256" },
		"alg lower case":          func(h, c map[string]any) { h["alg"] = "eddsa" },
		"alg missing":             func(h, c map[string]any) { delete(h, "alg") },
		"alg not a string":        func(h, c map[string]any) { h["alg"] = 1 },
		"typ is the token's":      func(h, c map[string]any) { h["typ"] = protocol.TokenType },
		"typ is JWT":              func(h, c map[string]any) { h["typ"] = "JWT" },
		"typ missing":             func(h, c map[string]any) { delete(h, "typ") },
		"jwk missing":             func(h, c map[string]any) { delete(h, "jwk") },
		"jwk null":                func(h, c map[string]any) { h["jwk"] = nil },
		"jwk a string":            func(h, c map[string]any) { h["jwk"] = "key" },
		"extra member jku":        func(h, c map[string]any) { h["jku"] = "https://evil.example/keys" },
		"extra member crit":       func(h, c map[string]any) { h["crit"] = []string{"x"} },
		"extra member kid":        func(h, c map[string]any) { h["kid"] = "k" },
		"extra member x5u":        func(h, c map[string]any) { h["x5u"] = "https://evil.example/c" },
		"member name in capitals": func(h, c map[string]any) { h["ALG"] = h["alg"]; delete(h, "alg") },
		"jwk with private d": func(h, c map[string]any) {
			h["jwk"] = map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64.Encode(pub), "d": b64.Encode(priv.Seed())}
		},
		"jwk with another member": func(h, c map[string]any) {
			h["jwk"] = map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64.Encode(pub), "kid": "k"}
		},
		"jwk wrong curve": func(h, c map[string]any) {
			h["jwk"] = map[string]any{"kty": "OKP", "crv": "X25519", "x": b64.Encode(pub)}
		},
		"jwk wrong type": func(h, c map[string]any) {
			h["jwk"] = map[string]any{"kty": "EC", "crv": "Ed25519", "x": b64.Encode(pub)}
		},
		"jwk short x": func(h, c map[string]any) {
			h["jwk"] = map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64.Encode(pub[:16])}
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(craft(t, priv, edit), expected())
			wantReason(t, err, protocol.ReasonProofInvalid)
		})
	}
}

func TestVerify_Step6_NotACompactJWS(t *testing.T) {
	valid := mustSign(t, signInput())
	parts := strings.Split(valid, ".")
	cases := map[string]string{
		"empty":                     "",
		"garbage":                   "not a proof",
		"one part":                  parts[0],
		"two parts":                 parts[0] + "." + parts[1],
		"four parts":                valid + ".x",
		"empty signature":           parts[0] + "." + parts[1] + ".",
		"padded part":               parts[0] + "=." + parts[1] + "." + parts[2],
		"unsigned (alg none shape)": parts[0] + "." + parts[1] + ".",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(in, expected())
			wantReason(t, err, protocol.ReasonProofInvalid)
		})
	}
}

// --- Step 7 comes before step 8 ---

func TestVerify_Step7_TheKeyMustBeTheOneTheTokenIsBoundTo(t *testing.T) {
	pub, _ := testKey()
	exp := expected()

	exp.BoundThumbprint = jwk.ThumbprintOf(pub)
	if _, err := Verify(mustSign(t, signInput()), exp); err != nil {
		t.Fatalf("the bound key was refused: %v", err)
	}

	exp.BoundThumbprint = jwk.ThumbprintOf(otherKey().Public().(ed25519.PublicKey))
	_, err := Verify(mustSign(t, signInput()), exp)
	wantReason(t, err, protocol.ReasonProofKeyMismatch)
}

// Spec order: the thumbprint is compared before the signature is checked, so a
// proof that fails both reports the key mismatch.
func TestVerify_Step7_ComesBeforeTheSignatureCheck(t *testing.T) {
	_, priv := testKey()
	// Header names the real key, but the proof is signed by another.
	forged := craftSignedBy(t, otherKey(), priv)

	exp := expected()
	exp.BoundThumbprint = jwk.ThumbprintOf(otherKey().Public().(ed25519.PublicKey))
	_, err := Verify(forged, exp)
	wantReason(t, err, protocol.ReasonProofKeyMismatch)

	// With no bound key, the same proof fails on its signature.
	_, err = Verify(forged, expected())
	wantReason(t, err, protocol.ReasonProofInvalid)
}

func craftSignedBy(t *testing.T, signer, headerKey ed25519.PrivateKey) string {
	t.Helper()
	h, c := validParts()
	h["jwk"] = jwk.FromPublicKey(headerKey.Public().(ed25519.PublicKey))
	p, err := jws.Sign(signer, h, c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// --- Step 8: the signature ---

func TestVerify_Step8_TheSignatureMustVerify(t *testing.T) {
	valid := mustSign(t, signInput())
	parts := strings.Split(valid, ".")

	sig, _ := b64.Decode(parts[2])
	sig[0] ^= 1
	flipped := parts[0] + "." + parts[1] + "." + b64.Encode(sig)

	// Valid header and signature, claims swapped for another proof's.
	otherIn := signInput()
	otherIn.Body = []byte("something else")
	other := strings.Split(mustSign(t, otherIn), ".")
	swapped := parts[0] + "." + other[1] + "." + parts[2]

	// Signed by a key other than the one the header names.
	_, priv := testKey()
	wrongSigner := craftSignedBy(t, otherKey(), priv)

	short := parts[0] + "." + parts[1] + "." + b64.Encode(make([]byte, 63))

	for name, in := range map[string]string{
		"one flipped bit":     flipped,
		"claims swapped":      swapped,
		"wrong signer":        wrongSigner,
		"signature too short": short,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(in, expected())
			wantReason(t, err, protocol.ReasonProofInvalid)
		})
	}
}

// --- Step 9: the claims ---

func TestVerify_Step9_EveryClaimMustBePresentAndWellFormed(t *testing.T) {
	_, priv := testKey()
	cases := map[string]func(h, c map[string]any){
		"htm missing":      func(h, c map[string]any) { delete(c, "htm") },
		"htu missing":      func(h, c map[string]any) { delete(c, "htu") },
		"iat missing":      func(h, c map[string]any) { delete(c, "iat") },
		"jti missing":      func(h, c map[string]any) { delete(c, "jti") },
		"bsh missing":      func(h, c map[string]any) { delete(c, "bsh") },
		"htm not a string": func(h, c map[string]any) { c["htm"] = 1 },
		"iat a string":     func(h, c map[string]any) { c["iat"] = fmt.Sprint(now.Unix()) },
		"iat a fraction":   func(h, c map[string]any) { c["iat"] = float64(now.Unix()) + 0.5 },
		"iat null":         func(h, c map[string]any) { c["iat"] = nil },
		"jti too short":    func(h, c map[string]any) { c["jti"] = b64.Encode(make([]byte, 15)) },
		"jti empty":        func(h, c map[string]any) { c["jti"] = "" },
		"jti not base64":   func(h, c map[string]any) { c["jti"] = "!!!not base64!!!" },
		"jti padded":       func(h, c map[string]any) { c["jti"] = b64.Encode(make([]byte, 16)) + "==" },
		"ath empty":        func(h, c map[string]any) { c["ath"] = "" },
		"ath not a string": func(h, c map[string]any) { c["ath"] = 5 },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(craft(t, priv, edit), expected())
			wantReason(t, err, protocol.ReasonProofInvalid)
		})
	}
}

func TestVerify_Step9_ExtraClaimsAreIgnored(t *testing.T) {
	_, priv := testKey()
	p := craft(t, priv, func(h, c map[string]any) { c["future"] = "claim" })
	if _, err := Verify(p, expected()); err != nil {
		t.Fatalf("an unknown claim was refused: %v", err)
	}
}

func TestVerify_Step9_TheProofMustBindThisRequest(t *testing.T) {
	cases := map[string]func(*Expected){
		"another method":                  func(e *Expected) { e.Method = "PUT" },
		"another path":                    func(e *Expected) { e.URL = "https://cp.example.com/atomity.agent.v1.AgentFacingService/GetToken" },
		"another host":                    func(e *Expected) { e.URL = "https://evil.example.com/atomity.agent.v1.AgentFacingService/Enroll" },
		"another scheme":                  func(e *Expected) { e.URL = strings.Replace(enrollURL, "https", "http", 1) },
		"another port":                    func(e *Expected) { e.URL = "https://cp.example.com:8443/atomity.agent.v1.AgentFacingService/Enroll" },
		"a different body":                func(e *Expected) { e.Body = []byte("another body") },
		"body with one more byte":         func(e *Expected) { e.Body = append(append([]byte{}, body...), 0) },
		"no body":                         func(e *Expected) { e.Body = nil },
		"a token the proof does not name": func(e *Expected) { e.Token = "some.token.here" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			exp := expected()
			edit(&exp)
			_, err := Verify(mustSign(t, signInput()), exp)
			wantReason(t, err, protocol.ReasonProofBindingMismatch)
		})
	}
}

func TestVerify_Step9_TheTokenHashMustMatch(t *testing.T) {
	in := signInput()
	in.Token = "aaa.bbb.ccc"

	exp := expected()
	exp.Token = "aaa.bbb.ddd"
	_, err := Verify(mustSign(t, in), exp)
	wantReason(t, err, protocol.ReasonProofBindingMismatch)

	// The proof names a token, the verifier has none to compare it with.
	_, err = Verify(mustSign(t, in), expected())
	wantReason(t, err, protocol.ReasonProofBindingMismatch)
}

// A proof captured from one request is useless for another: it is bound to the
// method, URL, body and token together.
func TestVerify_Step9_ACapturedProofCannotBeReusedForAnotherRequest(t *testing.T) {
	captured := mustSign(t, signInput())
	for name, edit := range map[string]func(*Expected){
		"later request, other body": func(e *Expected) { e.Body = []byte(`{"observations":[]}`) },
		"same body, other endpoint": func(e *Expected) { e.URL = "https://gw.example.com/v1/ingest" },
	} {
		exp := expected()
		edit(&exp)
		if _, err := Verify(captured, exp); err == nil {
			t.Errorf("%s: a captured proof was accepted", name)
		}
	}
}

// --- The time window ---

func proofAt(t *testing.T, at time.Time) string {
	t.Helper()
	in := signInput()
	in.Now = at
	return mustSign(t, in)
}

// Spec: a proof exactly at the window edge is accepted.
func TestVerify_Window_EdgesAreAcceptedAndJustBeyondIsStale(t *testing.T) {
	cases := []struct {
		name  string
		shift time.Duration
		ok    bool
	}{
		{"now", 0, true},
		{"60s old: exactly the edge", -60 * time.Second, true},
		{"60s ahead: exactly the edge", 60 * time.Second, true},
		{"59s old", -59 * time.Second, true},
		{"61s old", -61 * time.Second, false},
		{"61s ahead", 61 * time.Second, false},
		{"an hour old", -time.Hour, false},
		{"a day ahead", 24 * time.Hour, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Verify(proofAt(t, now.Add(c.shift)), expected())
			if c.ok {
				if err != nil {
					t.Fatalf("err = %v, want it accepted", err)
				}
				return
			}
			wantReason(t, err, protocol.ReasonProofStale)
		})
	}
}

func TestVerify_Window_AStaleErrorCarriesTheVerifiersTime(t *testing.T) {
	_, err := Verify(proofAt(t, now.Add(-5*time.Minute)), expected())
	var pe *protocol.Error
	if !errors.As(err, &pe) || pe.Reason != protocol.ReasonProofStale {
		t.Fatalf("err = %v", err)
	}
	if !pe.ServerTime.Equal(now) {
		t.Fatalf("ServerTime = %v, want the verifier's %v so the agent can correct its clock", pe.ServerTime, now)
	}
	if pe.Code() != protocol.CodeUnauthenticated {
		t.Fatalf("code = %s", pe.Code())
	}
}

func TestVerify_Window_CanBeConfigured(t *testing.T) {
	exp := expected()
	exp.Window = 5 * time.Second
	if _, err := Verify(proofAt(t, now.Add(-5*time.Second)), exp); err != nil {
		t.Fatalf("the edge of a 5s window was refused: %v", err)
	}
	_, err := Verify(proofAt(t, now.Add(-6*time.Second)), exp)
	wantReason(t, err, protocol.ReasonProofStale)
}

// The agent's fix for clock skew (spec: Agent clock): a server five minutes
// ahead makes every uncorrected proof stale, and the corrected one pass.
func TestVerify_Window_ClockSkewIsFixedByTheAgentsOffset(t *testing.T) {
	serverNow := now.Add(5 * time.Minute)
	exp := expected()
	exp.Now = serverNow

	_, err := Verify(proofAt(t, now), exp) // the agent's own, wrong clock
	wantReason(t, err, protocol.ReasonProofStale)

	if _, err := Verify(proofAt(t, serverNow), exp); err != nil { // corrected
		t.Fatalf("a corrected proof was refused: %v", err)
	}
}

// --- The order of the checks ---

// The spec checks htm, htu, then the window, then ath, then bsh, and stops at
// the first failure. The reason a caller sees depends on it.
func TestVerify_ChecksRunInTheSpecsOrder(t *testing.T) {
	stale := proofAt(t, now.Add(-time.Hour))

	exp := expected()
	exp.Method = "PUT" // wrong method AND stale
	_, err := Verify(stale, exp)
	wantReason(t, err, protocol.ReasonProofBindingMismatch)

	exp = expected()
	exp.URL = "https://other.example.com/x" // wrong URL AND stale
	_, err = Verify(stale, exp)
	wantReason(t, err, protocol.ReasonProofBindingMismatch)

	exp = expected()
	exp.Body = []byte("changed") // wrong body AND stale: the window comes first
	_, err = Verify(stale, exp)
	wantReason(t, err, protocol.ReasonProofStale)

	// Token hash is checked before the body hash.
	in := signInput()
	in.Token = "aaa.bbb.ccc"
	exp = expected()
	exp.Token = "aaa.bbb.ddd"
	exp.Body = []byte("changed")
	_, err = Verify(mustSign(t, in), exp)
	wantReason(t, err, protocol.ReasonProofBindingMismatch)
}

// A signature is checked before any claim is read, so claims of a forged
// proof never matter.
func TestVerify_TheSignatureIsCheckedBeforeTheClaims(t *testing.T) {
	_, priv := testKey()
	forged := craftSignedBy(t, otherKey(), priv) // claims are fine, signature is not
	_, err := Verify(forged, expected())
	wantReason(t, err, protocol.ReasonProofInvalid)

	// And a forged proof with stale claims reports the signature, not staleness.
	h, c := validParts()
	c["iat"] = now.Add(-time.Hour).Unix()
	h["jwk"] = jwk.FromPublicKey(priv.Public().(ed25519.PublicKey))
	staleForged, _ := jws.Sign(otherKey(), h, c)
	_, err = Verify(staleForged, expected())
	wantReason(t, err, protocol.ReasonProofInvalid)
}

// --- Misuse by the caller is not an authentication failure ---

func TestVerify_CallerMistakesAreNotProtocolErrors(t *testing.T) {
	valid := mustSign(t, signInput())
	for name, mutate := range map[string]func(*Expected){
		"no method":    func(e *Expected) { e.Method = "" },
		"no time":      func(e *Expected) { e.Now = time.Time{} },
		"relative URL": func(e *Expected) { e.URL = "/enroll" },
		"no URL":       func(e *Expected) { e.URL = "" },
	} {
		t.Run(name, func(t *testing.T) {
			exp := expected()
			mutate(&exp)
			_, err := Verify(valid, exp)
			if err == nil {
				t.Fatal("expected an error")
			}
			if _, isReason := protocol.ReasonOf(err); isReason {
				t.Fatalf("a configuration mistake was reported as an authentication failure: %v", err)
			}
		})
	}
}

// Failure messages are for logs and for callers. They must not repeat what the
// agent sent.
func TestVerify_ErrorsNeverEchoRequestValues(t *testing.T) {
	secret := "SECRET-VALUE-" + strings.Repeat("z", 20)
	_, priv := testKey()
	inputs := []string{
		craft(t, priv, func(h, c map[string]any) { c["htm"] = secret }),
		craft(t, priv, func(h, c map[string]any) { c["htu"] = secret }),
		craft(t, priv, func(h, c map[string]any) { h["jku"] = secret }),
		craft(t, priv, func(h, c map[string]any) { h["typ"] = secret }),
		craft(t, priv, func(h, c map[string]any) { h["alg"] = secret }),
		craft(t, priv, func(h, c map[string]any) { c["jti"] = secret }),
	}
	for i, in := range inputs {
		_, err := Verify(in, expected())
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("case %d: err = %v", i, err)
		}
	}
}

func TestVerified_IsIndependentOfTheInput(t *testing.T) {
	// Verify must not let a later call change an earlier result.
	a, _ := Verify(mustSign(t, signInput()), expected())
	snapshot := *a
	_, _ = Verify("garbage", expected())
	if *a != snapshot {
		t.Fatal("a result changed")
	}
}

// --- Fuzzing: Verify takes bytes from the network ---

func FuzzVerify(f *testing.F) {
	valid, _ := Sign(signInput())
	parts := strings.Split(valid, ".")
	f.Add(valid)
	f.Add("")
	f.Add("..")
	f.Add("a.b.c")
	f.Add(parts[0] + "." + parts[1] + ".")
	f.Add(parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[2])
	f.Add(strings.ToUpper(valid))
	f.Add(valid[:len(valid)/2])
	f.Add(parts[1] + "." + parts[0] + "." + parts[2])

	f.Fuzz(func(t *testing.T, in string) {
		v, err := Verify(in, expected())
		if err != nil {
			var pe *protocol.Error
			if !errors.As(err, &pe) {
				t.Fatalf("a failure that is not a *protocol.Error: %v", err)
			}
			if !pe.Reason.Known() {
				t.Fatalf("unknown reason %q", pe.Reason)
			}
			return
		}
		// If it was accepted, it must be a proof that this exact request could
		// have produced: anything else getting through is a hole.
		if v.Claims.HTM != "POST" || v.Claims.HTU != enrollURL || v.Claims.BSH != BodyHash(body) {
			t.Fatalf("accepted a proof that does not bind this request: %+v", v.Claims)
		}
		if _, err := v.Key.PublicKey(); err != nil {
			t.Fatalf("accepted a proof with an invalid key: %v", err)
		}
	})
}
