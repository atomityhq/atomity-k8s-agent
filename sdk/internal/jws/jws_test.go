package jws

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/atomityhq/atomity-k8s-agent/sdk/internal/b64"
)

// RFC 8037 appendix A: an Ed25519 key and a JWS made with it. These values come
// from the RFC, not from this code, so they pin the implementation to the
// standard instead of to itself.
const (
	rfcSeed      = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfcPublic    = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	rfcSigned    = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
	rfcSignature = "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
)

func rfcKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed, err := b64.Decode(rfcSeed)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if want := rfcPublic; b64.Encode(pub) != want {
		t.Fatalf("seed derives %s, RFC 8037 says %s", b64.Encode(pub), want)
	}
	return pub, priv
}

func TestRFC8037_TheExampleSignatureVerifiesAndIsReproduced(t *testing.T) {
	pub, priv := rfcKey(t)

	c, err := Parse(rfcSigned + "." + rfcSignature)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Verify(pub) {
		t.Fatal("the RFC 8037 example signature does not verify")
	}
	// Ed25519 is deterministic: signing the same input gives the same bytes.
	if got := b64.Encode(ed25519.Sign(priv, []byte(rfcSigned))); got != rfcSignature {
		t.Fatalf("signature = %s, RFC 8037 says %s", got, rfcSignature)
	}
}

func TestVerify_RejectsWhatDoesNotBelong(t *testing.T) {
	pub, _ := rfcKey(t)
	otherPub, _, _ := ed25519.GenerateKey(nil)

	c, _ := Parse(rfcSigned + "." + rfcSignature)
	if c.Verify(otherPub) {
		t.Fatal("verified under another key")
	}
	if c.Verify(pub[:31]) || c.Verify(nil) {
		t.Fatal("verified under a key of the wrong size")
	}

	// The signed bytes are the text as sent. Change one character of the payload.
	tampered := strings.Replace(rfcSigned, "RXhh", "RXhi", 1)
	c, err := Parse(tampered + "." + rfcSignature)
	if err != nil {
		t.Fatal(err)
	}
	if c.Verify(pub) {
		t.Fatal("verified a tampered payload")
	}

	short, err := Parse(rfcSigned + "." + b64.Encode(make([]byte, 63)))
	if err != nil {
		t.Fatal(err)
	}
	if short.Verify(pub) {
		t.Fatal("verified a signature of the wrong length")
	}
}

func TestParse_Shape(t *testing.T) {
	bad := map[string]string{
		"empty":           "",
		"no dots":         "abc",
		"two parts":       "abc.def",
		"four parts":      "abc.def.ghi.jkl",
		"empty header":    ".AAAA.AAAA",
		"empty payload":   "AAAA..AAAA",
		"empty signature": "AAAA.AAAA.",
		"padding":         "AAA=.AAAA.AAAA",
		"not base64url":   "AA+A.AAAA.AAAA",
		"newline inside":  "AAAA.AA\nAA.AAAA",
	}
	for name, in := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(in); err == nil {
				t.Fatalf("Parse(%q) accepted it", in)
			}
		})
	}
}

func TestSign_IsDeterministicAndParsesBack(t *testing.T) {
	_, priv := rfcKey(t)
	a, err := Sign(priv, map[string]any{"alg": "EdDSA"}, map[string]any{"n": 1})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Sign(priv, map[string]any{"alg": "EdDSA"}, map[string]any{"n": 1})
	if a != b {
		t.Fatal("equal inputs gave different output")
	}
	c, err := Parse(a)
	if err != nil || !c.Verify(priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("did not parse and verify: %v", err)
	}
	if _, err := Sign(priv[:10], nil, nil); err == nil {
		t.Fatal("signed with a short key")
	}
}

// encoding/json would match "ALG" to a field called alg. The protocol does not.
func TestObject_MatchesNamesExactly(t *testing.T) {
	m, err := Object([]byte(`{"ALG":"EdDSA","alg":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := String(m, "alg"); s != "x" {
		t.Fatalf(`"alg" = %q: a differently-cased name must not be taken for it`, s)
	}
	if err := OnlyMembers(map[string]json.RawMessage{"ALG": nil}, "alg"); err == nil {
		t.Fatal(`"ALG" was allowed where only "alg" is`)
	}
}

func TestObject_RefusesWhatIsNotOneObject(t *testing.T) {
	for name, in := range map[string]string{
		"array":         `[]`,
		"null":          `null`,
		"string":        `"x"`,
		"number":        `1`,
		"empty":         ``,
		"trailing data": `{} {}`,
		"trailing junk": `{}x`,
		"truncated":     `{"a":`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Object([]byte(in)); err == nil {
				t.Fatalf("Object(%s) accepted it", in)
			}
		})
	}
}

// encoding/json decodes null into a string or an integer without an error,
// leaving "" or 0. A strict parser must not let that pass for a value.
func TestMembers_NullIsNotAValue(t *testing.T) {
	m, _ := Object([]byte(`{"s":null,"n":null,"padded":  null  }`))
	for _, name := range []string{"s", "n", "padded"} {
		if v, err := String(m, name); err == nil {
			t.Errorf("String(%s) = %q, want an error", name, v)
		}
		if v, err := Int64(m, name); err == nil {
			t.Errorf("Int64(%s) = %d, want an error", name, v)
		}
	}
}

func TestMembers_AreTypeChecked(t *testing.T) {
	m, _ := Object([]byte(`{"s":"x","n":5,"f":1.5,"b":true,"big":99999999999999999999}`))
	if v, err := String(m, "s"); err != nil || v != "x" {
		t.Fatalf("String: %q, %v", v, err)
	}
	if v, err := Int64(m, "n"); err != nil || v != 5 {
		t.Fatalf("Int64: %d, %v", v, err)
	}
	for _, name := range []string{"n", "b", "missing"} {
		if _, err := String(m, name); err == nil {
			t.Fatalf("String accepted %q", name)
		}
	}
	for _, name := range []string{"s", "f", "b", "big", "missing"} {
		if _, err := Int64(m, name); err == nil {
			t.Fatalf("Int64 accepted %q", name)
		}
	}
}
