package clock

import (
	"sync"
	"testing"
	"time"
)

var epoch = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func fixed() Clock { return Func(func() time.Time { return epoch }) }

func TestSystem_IsRoughlyNow(t *testing.T) {
	if d := time.Since(System{}.Now()); d < 0 || d > time.Minute {
		t.Fatalf("System.Now is %v off", d)
	}
}

func TestOffset_StartsAtZeroAndDefaultsToTheSystemClock(t *testing.T) {
	o := NewOffset(nil)
	if o.Current() != 0 {
		t.Fatalf("starts at %v", o.Current())
	}
	if d := time.Since(o.Now()); d < 0 || d > time.Minute {
		t.Fatalf("nil base: Now is %v off", d)
	}
}

// The spec's test: a server clock five minutes ahead.
func TestOffset_CorrectsForAServerClockAhead(t *testing.T) {
	o := NewOffset(fixed())
	server := epoch.Add(5 * time.Minute)

	if !o.ObserveDate(server.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")) {
		t.Fatal("a valid Date header was not used")
	}
	if o.Current() != 5*time.Minute {
		t.Fatalf("offset = %v, want 5m", o.Current())
	}
	if got := o.Now(); !got.Equal(server) {
		t.Fatalf("Now = %v, want the server's %v", got, server)
	}
}

func TestOffset_CorrectsForAServerClockBehind(t *testing.T) {
	o := NewOffset(fixed())
	o.ObserveServerTime(epoch.Add(-90 * time.Second))
	if o.Current() != -90*time.Second || !o.Now().Equal(epoch.Add(-90*time.Second)) {
		t.Fatalf("offset = %v, Now = %v", o.Current(), o.Now())
	}
}

// Spec: an unparseable Date header is ignored and the last offset is kept.
func TestObserveDate_UnparseableKeepsTheLastOffset(t *testing.T) {
	o := NewOffset(fixed())
	o.ObserveServerTime(epoch.Add(5 * time.Minute))
	before := o.Current()

	for _, h := range []string{"", "not a date", "Mon, 32 Jan 2026 25:61:61 GMT", "2026-10-10T12:00:00Z", "0"} {
		if o.ObserveDate(h) {
			t.Errorf("ObserveDate(%q) was used", h)
		}
		if o.Current() != before {
			t.Fatalf("ObserveDate(%q) changed the offset to %v", h, o.Current())
		}
	}
}

func TestObserveDate_AcceptsEveryHTTPDateFormat(t *testing.T) {
	server := epoch.Add(2 * time.Minute)
	for name, h := range map[string]string{
		"IMF-fixdate": server.Format("Mon, 02 Jan 2006 15:04:05 GMT"),
		"RFC 850":     server.Format("Monday, 02-Jan-06 15:04:05 GMT"),
		"asctime":     server.Format("Mon Jan _2 15:04:05 2006"),
	} {
		t.Run(name, func(t *testing.T) {
			o := NewOffset(fixed())
			if !o.ObserveDate(h) || o.Current() != 2*time.Minute {
				t.Fatalf("offset = %v after %q", o.Current(), h)
			}
		})
	}
}

func TestOffset_FollowsTheBaseClock(t *testing.T) {
	now := epoch
	var mu sync.Mutex
	o := NewOffset(Func(func() time.Time { mu.Lock(); defer mu.Unlock(); return now }))
	o.ObserveServerTime(epoch.Add(time.Minute))

	mu.Lock()
	now = now.Add(10 * time.Second)
	mu.Unlock()

	if want := epoch.Add(10*time.Second + time.Minute); !o.Now().Equal(want) {
		t.Fatalf("Now = %v, want %v: the offset must be applied to a moving clock", o.Now(), want)
	}
}

func TestOffset_IsSafeForConcurrentUse(t *testing.T) {
	o := NewOffset(nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			o.ObserveServerTime(time.Now().Add(time.Duration(i) * time.Second))
			_ = o.Now()
			_ = o.Current()
			o.ObserveDate("garbage")
		}(i)
	}
	wg.Wait()
}
