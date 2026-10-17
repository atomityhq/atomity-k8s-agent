package protocol

import (
	"errors"
	"fmt"
	"testing"
)

// The reason strings and their codes, copied from the spec's Errors table.
// The agent's behavior keys off these exact strings, so they are pinned here
// separately from the code that defines them.
func TestReasons_MatchTheSpec(t *testing.T) {
	want := map[Reason]Code{
		"token_missing":            CodeUnauthenticated,
		"proof_missing":            CodeUnauthenticated,
		"token_malformed":          CodeUnauthenticated,
		"proof_invalid":            CodeUnauthenticated,
		"token_expired":            CodeUnauthenticated,
		"token_signature_invalid":  CodeUnauthenticated,
		"token_kid_unknown":        CodeUnauthenticated,
		"proof_key_mismatch":       CodeUnauthenticated,
		"proof_stale":              CodeUnauthenticated,
		"proof_replayed":           CodeUnauthenticated,
		"proof_binding_mismatch":   CodeUnauthenticated,
		"agent_unknown":            CodeUnauthenticated,
		"credential_invalid":       CodeUnauthenticated,
		"token_not_yet_valid":      CodeUnauthenticated,
		"token_claims_invalid":     CodeUnauthenticated,
		"token_audience_mismatch":  CodePermissionDenied,
		"token_kind_mismatch":      CodePermissionDenied,
		"token_scope_insufficient": CodePermissionDenied,
		"agent_revoked":            CodePermissionDenied,
		"rate_limited":             CodeResourceExhausted,
		"protocol_unsupported":     CodeUnimplemented,
	}
	got := Reasons()
	if len(got) != len(want) {
		t.Fatalf("%d reasons defined, the spec lists %d", len(got), len(want))
	}
	for r, code := range want {
		if !r.Known() {
			t.Errorf("%q is not defined", r)
		}
		if r.Code() != code {
			t.Errorf("%q has code %s, the spec says %s", r, r.Code(), code)
		}
	}
	for _, r := range got {
		if _, ok := want[r]; !ok {
			t.Errorf("%q is defined but not in the spec", r)
		}
	}
}

func TestUnknownReasonIsUnauthenticated(t *testing.T) {
	r := Reason("something_new")
	if r.Known() || r.Code() != CodeUnauthenticated {
		t.Fatalf("known=%v code=%s", r.Known(), r.Code())
	}
}

func TestError_MatchesByReason(t *testing.T) {
	err := fmt.Errorf("verifying: %w", Fail(ReasonProofStale, "outside the window"))

	if !errors.Is(err, &Error{Reason: ReasonProofStale}) {
		t.Fatal("errors.Is did not match on the reason")
	}
	if errors.Is(err, &Error{Reason: ReasonProofInvalid}) {
		t.Fatal("errors.Is matched a different reason")
	}
	if r, ok := ReasonOf(err); !ok || r != ReasonProofStale {
		t.Fatalf("ReasonOf = %q, %v", r, ok)
	}
	if _, ok := ReasonOf(errors.New("plain")); ok {
		t.Fatal("ReasonOf found a reason in a plain error")
	}
	if got := Fail(ReasonAgentRevoked, "").Error(); got != "agent_revoked" {
		t.Fatalf("Error() = %q", got)
	}
	if got := Fail(ReasonAgentRevoked, "gone").Code(); got != CodePermissionDenied {
		t.Fatalf("Code() = %s", got)
	}
}

// Identifiers fixed for protocol version 1 (spec: Identifiers and versioning).
func TestIdentifiers_MatchTheSpec(t *testing.T) {
	for name, c := range map[string][2]string{
		"issuer":      {Issuer, "atomity-agent"},
		"audience":    {AudienceK8s, "k8s-gateway"},
		"kind":        {KindK8s, "k8s"},
		"binding":     {BindingTypeK8sCluster, "k8s.cluster"},
		"scope":       {ScopeIngest, "ingest"},
		"token typ":   {TokenType, "agent-token+jwt"},
		"proof typ":   {ProofType, "agent-proof+jwt"},
		"algorithm":   {Algorithm, "EdDSA"},
		"credential":  {CredentialPrefix, "atm_enr_"},
		"auth header": {HeaderAuthorization, "Authorization"},
		"proof hdr":   {HeaderProof, "Agent-Proof"},
		"new proof":   {HeaderProofNew, "Agent-Proof-New"},
		"scheme":      {AuthScheme, "AgentToken"},
	} {
		if c[0] != c[1] {
			t.Errorf("%s = %q, the spec says %q", name, c[0], c[1])
		}
	}
	if ProofWindow.Seconds() != 60 {
		t.Errorf("proof window = %v, the spec says 60 seconds", ProofWindow)
	}
	if JTIMinBytes*8 != 128 {
		t.Errorf("jti minimum = %d bits, the spec says 128", JTIMinBytes*8)
	}
}
