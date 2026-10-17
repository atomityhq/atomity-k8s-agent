package jwk

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/atomityhq/atomity-k8s-agent/sdk/internal/b64"
)

// RFC 8037 appendix A: the example Ed25519 key and its JWK thumbprint.
const (
	rfcSeed       = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfcX          = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	rfcThumbprint = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
)

func TestRFC8037_Thumbprint(t *testing.T) {
	p, err := Parse([]byte(`{"kty":"OKP","crv":"Ed25519","x":"` + rfcX + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Thumbprint()
	if err != nil || got != rfcThumbprint {
		t.Fatalf("thumbprint = %q, %v; RFC 8037 says %q", got, err, rfcThumbprint)
	}

	// The same value from the key bytes, and from the seed in the RFC.
	seed, _ := b64.Decode(rfcSeed)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if got := ThumbprintOf(pub); got != rfcThumbprint {
		t.Fatalf("ThumbprintOf = %q, want %q", got, rfcThumbprint)
	}
	if FromPublicKey(pub).X != rfcX {
		t.Fatalf("FromPublicKey x = %q, want %q", FromPublicKey(pub).X, rfcX)
	}
}

// The thumbprint is of the key, not of how a JWK was typed out.
func TestThumbprint_DoesNotDependOnHowTheJWKIsWritten(t *testing.T) {
	forms := []string{
		`{"kty":"OKP","crv":"Ed25519","x":"` + rfcX + `"}`,
		`{"x":"` + rfcX + `","crv":"Ed25519","kty":"OKP"}`,
		"{ \"crv\" : \"Ed25519\",\n  \"kty\" : \"OKP\",\n  \"x\" : \"" + rfcX + "\" }",
	}
	for _, f := range forms {
		p, err := Parse([]byte(f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if got, _ := p.Thumbprint(); got != rfcThumbprint {
			t.Fatalf("%s: thumbprint %q", f, got)
		}
	}
}

func TestParse_RefusesAnythingButAPublicEd25519Key(t *testing.T) {
	x := rfcX
	short := b64.Encode(make([]byte, 31))
	long := b64.Encode(make([]byte, 33))
	cases := map[string]string{
		"private d":       `{"kty":"OKP","crv":"Ed25519","x":"` + x + `","d":"` + rfcSeed + `"}`,
		"private d only":  `{"kty":"OKP","crv":"Ed25519","d":"` + rfcSeed + `"}`,
		"other member":    `{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"k"}`,
		"use member":      `{"kty":"OKP","crv":"Ed25519","x":"` + x + `","use":"sig"}`,
		"wrong kty":       `{"kty":"EC","crv":"Ed25519","x":"` + x + `"}`,
		"wrong crv":       `{"kty":"OKP","crv":"Ed448","x":"` + x + `"}`,
		"x25519":          `{"kty":"OKP","crv":"X25519","x":"` + x + `"}`,
		"missing kty":     `{"crv":"Ed25519","x":"` + x + `"}`,
		"missing crv":     `{"kty":"OKP","x":"` + x + `"}`,
		"missing x":       `{"kty":"OKP","crv":"Ed25519"}`,
		"x too short":     `{"kty":"OKP","crv":"Ed25519","x":"` + short + `"}`,
		"x too long":      `{"kty":"OKP","crv":"Ed25519","x":"` + long + `"}`,
		"x padded":        `{"kty":"OKP","crv":"Ed25519","x":"` + x + `="}`,
		"x not base64url": `{"kty":"OKP","crv":"Ed25519","x":"` + strings.Replace(x, "_", "/", 1) + `"}`,
		"x with newline":  `{"kty":"OKP","crv":"Ed25519","x":"` + x[:10] + `\n` + x[10:] + `"}`,
		"x not a string":  `{"kty":"OKP","crv":"Ed25519","x":5}`,
		"upper-case name": `{"KTY":"OKP","crv":"Ed25519","x":"` + x + `"}`,
		"not an object":   `[]`,
		"empty":           ``,
		"trailing data":   `{"kty":"OKP","crv":"Ed25519","x":"` + x + `"} {}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if p, err := Parse([]byte(in)); err == nil {
				t.Fatalf("Parse accepted %s as %+v", in, p)
			}
		})
	}
}

func TestParse_NamesPrivateMaterial(t *testing.T) {
	_, err := Parse([]byte(`{"kty":"OKP","crv":"Ed25519","x":"` + rfcX + `","d":"` + rfcSeed + `"}`))
	if !errors.Is(err, ErrPrivateMaterial) {
		t.Fatalf("err = %v, want ErrPrivateMaterial", err)
	}
	// The error must not repeat the secret.
	if strings.Contains(err.Error(), rfcSeed) {
		t.Fatal("the error message contains the private key")
	}
}

// Decoding into a Public must go through the same checks.
func TestUnmarshalJSON_RunsTheSameChecks(t *testing.T) {
	var ok Public
	if err := json.Unmarshal([]byte(`{"kty":"OKP","crv":"Ed25519","x":"`+rfcX+`"}`), &ok); err != nil || ok.X != rfcX {
		t.Fatalf("valid key: %+v, %v", ok, err)
	}
	var bad Public
	if err := json.Unmarshal([]byte(`{"kty":"OKP","crv":"Ed25519","x":"`+rfcX+`","d":"`+rfcSeed+`"}`), &bad); err == nil {
		t.Fatal("decoded a key with private material")
	}
}

func TestZeroValueIsNotAKey(t *testing.T) {
	var p Public
	if _, err := p.PublicKey(); err == nil {
		t.Fatal("the zero value is a valid key")
	}
	if _, err := p.Thumbprint(); err == nil {
		t.Fatal("the zero value has a thumbprint")
	}
	if _, err := p.MarshalCanonical(); err == nil {
		t.Fatal("the zero value marshals")
	}
}

func TestGenerate_IsDeterministicWithAReaderAndRandomWithout(t *testing.T) {
	seed := bytes.NewReader(bytes.Repeat([]byte{7}, 64))
	pub1, priv1, err := Generate(seed)
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, _ := Generate(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if !pub1.Equal(pub2) {
		t.Fatal("the same entropy gave different keys")
	}
	if !priv1.Public().(ed25519.PublicKey).Equal(pub1) {
		t.Fatal("public key does not belong to the private key")
	}

	a, _, _ := Generate(nil)
	b, _, _ := Generate(nil)
	if a.Equal(b) {
		t.Fatal("two random keys were equal")
	}
	if _, _, err := Generate(bytes.NewReader([]byte{1, 2, 3})); err == nil {
		t.Fatal("generated a key from too little entropy")
	}
}

func TestMarshalCanonical_FixedOrderAndRoundTrips(t *testing.T) {
	p := Public{Kty: "OKP", Crv: "Ed25519", X: rfcX}
	got, err := p.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"kty":"OKP","crv":"Ed25519","x":"` + rfcX + `"}`
	if string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	back, err := Parse(got)
	if err != nil || back != p {
		t.Fatalf("round trip: %+v, %v", back, err)
	}
}

func TestEqualThumbprints(t *testing.T) {
	if !EqualThumbprints(rfcThumbprint, rfcThumbprint) {
		t.Fatal("equal thumbprints compared unequal")
	}
	for _, other := range []string{"", rfcThumbprint + "x", rfcThumbprint[:len(rfcThumbprint)-1], "A" + rfcThumbprint[1:]} {
		if EqualThumbprints(rfcThumbprint, other) {
			t.Fatalf("%q equals the thumbprint", other)
		}
	}
}
