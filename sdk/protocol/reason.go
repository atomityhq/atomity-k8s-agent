package protocol

import (
	"errors"
	"time"
)

// Reason is the stable machine-readable cause of an authentication failure.
// The agent's behavior depends on the Reason, never on a human-readable
// message. The values are part of protocol version 1.
type Reason string

const (
	// UNAUTHENTICATED
	ReasonTokenMissing          Reason = "token_missing"
	ReasonProofMissing          Reason = "proof_missing"
	ReasonTokenMalformed        Reason = "token_malformed"
	ReasonProofInvalid          Reason = "proof_invalid"
	ReasonTokenExpired          Reason = "token_expired"
	ReasonTokenSignatureInvalid Reason = "token_signature_invalid"
	ReasonTokenKIDUnknown       Reason = "token_kid_unknown"
	ReasonProofKeyMismatch      Reason = "proof_key_mismatch"
	ReasonProofStale            Reason = "proof_stale"
	ReasonProofReplayed         Reason = "proof_replayed"
	ReasonProofBindingMismatch  Reason = "proof_binding_mismatch"
	ReasonAgentUnknown          Reason = "agent_unknown"
	ReasonCredentialInvalid     Reason = "credential_invalid"
	ReasonTokenNotYetValid      Reason = "token_not_yet_valid"
	ReasonTokenClaimsInvalid    Reason = "token_claims_invalid"

	// PERMISSION_DENIED
	ReasonTokenAudienceMismatch  Reason = "token_audience_mismatch"
	ReasonTokenKindMismatch      Reason = "token_kind_mismatch"
	ReasonTokenScopeInsufficient Reason = "token_scope_insufficient"
	ReasonAgentRevoked           Reason = "agent_revoked"

	// RESOURCE_EXHAUSTED
	ReasonRateLimited Reason = "rate_limited"

	// UNIMPLEMENTED
	ReasonProtocolUnsupported Reason = "protocol_unsupported"
)

// Code is the gRPC-equivalent status of a failure. The Connect protocol maps
// its error codes one to one onto gRPC's, so these names serve both. The SDK
// carries its own type so that it does not depend on a gRPC or Connect
// library.
type Code string

const (
	CodeUnauthenticated   Code = "UNAUTHENTICATED"
	CodePermissionDenied  Code = "PERMISSION_DENIED"
	CodeResourceExhausted Code = "RESOURCE_EXHAUSTED"
	CodeUnimplemented     Code = "UNIMPLEMENTED"
)

var codes = map[Reason]Code{
	ReasonTokenMissing:           CodeUnauthenticated,
	ReasonProofMissing:           CodeUnauthenticated,
	ReasonTokenMalformed:         CodeUnauthenticated,
	ReasonProofInvalid:           CodeUnauthenticated,
	ReasonTokenExpired:           CodeUnauthenticated,
	ReasonTokenSignatureInvalid:  CodeUnauthenticated,
	ReasonTokenKIDUnknown:        CodeUnauthenticated,
	ReasonProofKeyMismatch:       CodeUnauthenticated,
	ReasonProofStale:             CodeUnauthenticated,
	ReasonProofReplayed:          CodeUnauthenticated,
	ReasonProofBindingMismatch:   CodeUnauthenticated,
	ReasonAgentUnknown:           CodeUnauthenticated,
	ReasonCredentialInvalid:      CodeUnauthenticated,
	ReasonTokenNotYetValid:       CodeUnauthenticated,
	ReasonTokenClaimsInvalid:     CodeUnauthenticated,
	ReasonTokenAudienceMismatch:  CodePermissionDenied,
	ReasonTokenKindMismatch:      CodePermissionDenied,
	ReasonTokenScopeInsufficient: CodePermissionDenied,
	ReasonAgentRevoked:           CodePermissionDenied,
	ReasonRateLimited:            CodeResourceExhausted,
	ReasonProtocolUnsupported:    CodeUnimplemented,
}

// Known reports whether r is a reason defined by protocol version 1.
func (r Reason) Known() bool { _, ok := codes[r]; return ok }

// Code returns the status that goes with the reason. An unknown reason is
// UNAUTHENTICATED, the safe default for something we cannot classify.
func (r Reason) Code() Code {
	if c, ok := codes[r]; ok {
		return c
	}
	return CodeUnauthenticated
}

// Reasons returns every reason defined by protocol version 1, in no
// particular order.
func Reasons() []Reason {
	out := make([]Reason, 0, len(codes))
	for r := range codes {
		out = append(out, r)
	}
	return out
}

// Error is an authentication failure with its stable Reason.
//
// Detail is a short fixed description for logs. It never contains a value from
// the request, so it is safe to log and to return.
type Error struct {
	Reason Reason
	Detail string

	// ServerTime is set for ReasonProofStale: the verifier's clock when it
	// rejected the proof, so the agent can correct its own (spec D13).
	ServerTime time.Time
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return string(e.Reason)
	}
	return string(e.Reason) + ": " + e.Detail
}

// Code returns the status for the error's reason.
func (e *Error) Code() Code { return e.Reason.Code() }

// Is makes errors.Is(err, &Error{Reason: r}) match on the Reason alone.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Reason == e.Reason
}

// Fail returns an Error with a Reason and a fixed Detail.
func Fail(r Reason, detail string) *Error { return &Error{Reason: r, Detail: detail} }

// ReasonOf returns the Reason of err if err is or wraps an *Error.
func ReasonOf(err error) (Reason, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason, true
	}
	return "", false
}
