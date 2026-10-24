package app

import (
	"testing"
	"time"
)

func TestFailLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	l := newFailLimiter()
	l.now = func() time.Time { return now }
	failN := func(n int) {
		for i := 0; i < n; i++ {
			l.fail("h")
		}
	}

	failN(maxFailures)
	if !l.blocked("h") {
		t.Fatal("not locked after max failures")
	}
	now = now.Add(lockDuration)
	failN(maxFailures)
	now = now.Add(lockDuration)
	if !l.blocked("h") {
		t.Error("second lockout did not double")
	}

	now = now.Add(maxLock)
	l.succeed("h")
	failN(maxFailures - 1)
	if l.blocked("h") {
		t.Error("success did not clear the record")
	}

	now = now.Add(failWindow + time.Second)
	l.fail("h")
	if l.blocked("h") {
		t.Error("old failures outside the window still counted")
	}
}

func TestLockForNeverOverflows(t *testing.T) {
	for _, locks := range []int{1, 2, 7, 29, 64, 1000} {
		if d := lockFor(locks); d <= 0 || d > maxLock {
			t.Errorf("lockFor(%d) = %v", locks, d)
		}
	}
	if lockFor(2) != 2*lockDuration {
		t.Errorf("lockFor(2) = %v, want doubling", lockFor(2))
	}
}
