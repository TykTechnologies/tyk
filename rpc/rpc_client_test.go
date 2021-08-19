package rpc

import "testing"

func TestRecoveryFromEmregencyMode(t *testing.T) {
	if IsEmergencyMode() {
		t.Fatal("expected not to be in emergency mode before initiating login attempt")
	}
	hasAPIKey := func() bool { return true }
	// group login has the same recovery api so we don't need to test for it.
	isGroup := func() bool { return false }

	ok := doLoginWithRetries(func() error {
		return errLogFailed
	}, func() error {
		return errLogFailed
	}, hasAPIKey, isGroup)
	if ok {
		t.Fatal("expected to fail login")
	}
	if !IsEmergencyMode() {
		t.Fatal("expected to be in emergency mode")
	}
	// Lets succeed after second retry
	x := 0
	ok = doLoginWithRetries(func() error {
		if x == 0 {
			x++
			return errLogFailed
		}
		return nil
	}, func() error {
		return errLogFailed
	}, hasAPIKey, isGroup)
	if !ok {
		t.Fatal("expected login to succeed")
	}
	if IsEmergencyMode() {
		t.Fatal("expected to recover from emergency mode")
	}
}
