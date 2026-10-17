// Package clock is the time source of the protocol code.
//
// Verification and signing take the time from a Clock that the caller
// injects, never from the system directly, so tests can pin it.
package clock

import (
	"net/http"
	"sync"
	"time"
)

// Clock tells the time.
type Clock interface {
	Now() time.Time
}

// System is the real clock.
type System struct{}

// Now returns the current time.
func (System) Now() time.Time { return time.Now() }

// Func adapts a function to a Clock.
type Func func() time.Time

// Now calls f.
func (f Func) Now() time.Time { return f() }

// Offset is the agent's view of the server's clock (spec: Agent clock).
//
// It keeps the difference between the server's clock and the agent's own,
// measured from the HTTP Date header of any response, or from the server time
// carried by a stale-proof error. Now returns the agent's time corrected by
// that difference, and is what the agent signs into the `iat` of its proofs.
//
// The offset affects only the `iat` the agent writes into its own proofs.
// Nothing else is corrected, and a proof stays bound to one request by its
// other claims.
type Offset struct {
	base Clock

	mu     sync.Mutex
	offset time.Duration
}

// NewOffset returns an Offset over base. A nil base means the system clock.
// The offset starts at zero.
func NewOffset(base Clock) *Offset {
	if base == nil {
		base = System{}
	}
	return &Offset{base: base}
}

// Now returns the base time corrected by the current offset.
func (o *Offset) Now() time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.base.Now().Add(o.offset)
}

// Current returns the offset: server time minus the agent's time. A positive
// value means the agent's clock is behind.
func (o *Offset) Current() time.Duration {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.offset
}

// ObserveDate updates the offset from an HTTP Date header value. A value that
// does not parse is ignored and the last offset is kept; the result says
// whether the header was used.
func (o *Offset) ObserveDate(header string) bool {
	t, err := http.ParseTime(header)
	if err != nil {
		return false
	}
	o.ObserveServerTime(t)
	return true
}

// ObserveServerTime updates the offset from a time the server reported as its
// own, taken to be the time right now.
func (o *Offset) ObserveServerTime(server time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.offset = server.Sub(o.base.Now())
}
