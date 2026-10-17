package b64

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, in := range [][]byte{{}, {0}, {0xff}, []byte("hello"), bytes.Repeat([]byte{0xAB}, 32)} {
		got, err := Decode(Encode(in))
		if err != nil || !bytes.Equal(got, in) {
			t.Fatalf("round trip of %x: %x, %v", in, got, err)
		}
	}
}

// Each of these would let two different strings stand for the same bytes.
func TestDecode_RefusesAnythingButCanonicalBase64URL(t *testing.T) {
	refused := map[string]string{
		"padding":                     "AAA=",
		"padding on a full block":     "AAAA====",
		"standard alphabet plus":      "ab+d",
		"standard alphabet slash":     "ab/d",
		"line feed":                   "AAAA\n",
		"carriage return":             "AA\rAA",
		"space":                       "AA AA",
		"non-zero trailing bits":      "AB", // 12 bits for one byte: the last 4 are not zero
		"one character is not a byte": "A",
	}
	for name, in := range refused {
		t.Run(name, func(t *testing.T) {
			if got, err := Decode(in); err == nil {
				t.Fatalf("Decode(%q) = %x, want an error", in, got)
			}
		})
	}
}
