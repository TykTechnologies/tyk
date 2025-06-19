package rpc

import (
	"testing"
)

func TestRecoveryFromEmergencyMode(t *testing.T) {
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

func TestClientIsConnected(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		connected bool
		expected  bool
	}{
		{
			name:      "When client is connected and not in emergency mode",
			connected: true,
			expected:  true,
		},
		{
			name:      "When client is disconnected and not in emergency mode",
			connected: false,
			expected:  false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			r := rpcOpts{}
			r.clientIsConnected.Store(tt.connected)
			defer func() {
				r.clientIsConnected.Store(false)
			}()

			got := r.ClientIsConnected()
			if got != tt.expected {
				t.Errorf("ClientIsConnected() = %v, want %v", got, tt.expected)
			}
		})
	}
}
