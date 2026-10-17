// Package protocol holds the values that are fixed for agent authentication
// protocol version 1: identifiers, header names, defaults, and the stable
// failure reasons.
//
// A change to any identifier here, or to a token or proof format, is a new
// protocol version, never an edit in place.
package protocol

import "time"

// Identifiers fixed for protocol version 1.
const (
	// Issuer is the access token issuer (the `iss` claim).
	Issuer = "atomity-agent"

	// AudienceK8s is the audience of access tokens for Kubernetes agents. The
	// control plane derives it from the agent kind; an agent cannot ask for one.
	AudienceK8s = "k8s-gateway"

	// KindK8s is the kind of a Kubernetes agent.
	KindK8s = "k8s"

	// BindingTypeK8sCluster is the binding type of a Kubernetes agent. The
	// binding id is the cluster id.
	BindingTypeK8sCluster = "k8s.cluster"

	// ScopeIngest is the only scope an agent token carries.
	ScopeIngest = "ingest"

	// TokenType and ProofType are the JOSE `typ` header values.
	TokenType = "agent-token+jwt"
	ProofType = "agent-proof+jwt"

	// Algorithm is the only signature algorithm: Ed25519.
	Algorithm = "EdDSA"

	// CredentialPrefix starts every enrollment credential, so leaked ones are
	// easy to scan for.
	CredentialPrefix = "atm_enr_"
)

// HTTP header names.
const (
	HeaderAuthorization = "Authorization"
	HeaderProof         = "Agent-Proof"
	// HeaderProofNew is reserved for RotateKey.
	HeaderProofNew = "Agent-Proof-New"

	// AuthScheme is the Authorization scheme: "AgentToken <jwt>".
	AuthScheme = "AgentToken"
)

// Defaults. In a deployment these are configuration. They are constants here
// only because the proof window is part of what a proof means, and the agent
// and the verifier must agree on it.
const (
	// ProofWindow is how far a proof's `iat` may be from the verifier's clock,
	// on either side. A proof exactly at the edge is accepted.
	ProofWindow = 60 * time.Second
)

// JTIMinBytes is the least entropy a proof's `jti` must carry: 128 bits.
const JTIMinBytes = 16
