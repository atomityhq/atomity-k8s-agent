# atomity-k8s-agent

The open-source Kubernetes agent for Atomity, and the SDK it shares with
Atomity's services.

The agent runs inside your cluster and only ever pushes data outbound. Atomity
never holds credentials for your cluster and never connects into it.

> **Status:** early development. The `sdk` module is the first part. The
> agent itself is not here yet.

## Layout

| Path | What it is |
| --- | --- |
| `sdk/` | Go module `github.com/atomityhq/atomity-k8s-agent/sdk`. The agent authentication protocol: keys and thumbprints, request proofs, error reasons, and a clock that corrects for skew. Standard library only. |
| `scripts/check-public.sh` | Fails if anything private (an internal module path or hostname) appears in this repository. |

## Authentication protocol

An agent proves who it is with an Ed25519 key it generates itself in the
cluster. Every request carries a proof signed with that key, bound to the
request's method, URL and body. The private key never leaves the cluster, and
a captured proof cannot be reused for any other request.

See `sdk/proof` for the proof format and how it is verified.

## Development

```sh
cd sdk
go vet ./...
go test -race ./...
go test -run '^$' -fuzz=FuzzVerify -fuzztime=30s ./proof   # Verify takes network input

cd ..
scripts/check-public.sh
```

Requires Go 1.25 or later.
