package gateway

import (
	"testing"
	"time"
)

func TestDRLNotificationInitialJitter(t *testing.T) {
	t.Parallel()

	if got := drlNotificationInitialJitter(0); got != 0 {
		t.Fatalf("drlNotificationInitialJitter(0) = %s, want 0", got)
	}
	if got := drlNotificationInitialJitter(-time.Second); got != 0 {
		t.Fatalf("drlNotificationInitialJitter(-1s) = %s, want 0", got)
	}

	interval := 10 * time.Millisecond
	if got := drlNotificationInitialJitter(interval); got < 0 || got >= interval {
		t.Fatalf("drlNotificationInitialJitter(%s) = %s, want within [0,%s)", interval, got, interval)
	}
}

func TestNotifyCurrentServerStatusIfReadySkipsBeforeControlPlaneReady(t *testing.T) {
	t.Parallel()

	gw := &Gateway{}

	published, idle := gw.notifyCurrentServerStatusIfReady(time.Now().Add(-time.Hour))
	if published {
		t.Fatal("notifyCurrentServerStatusIfReady() published before control plane was ready")
	}
	if idle {
		t.Fatal("notifyCurrentServerStatusIfReady() reported idle before control plane was ready")
	}
}

func TestNotifyCurrentServerStatusIfReadyThrottlesIdleGateways(t *testing.T) {
	t.Parallel()

	gw := &Gateway{}
	gw.controlPlaneReady.Store(true)

	published, idle := gw.notifyCurrentServerStatusIfReady(time.Now())
	if published {
		t.Fatal("notifyCurrentServerStatusIfReady() published inside idle suppression window")
	}
	if !idle {
		t.Fatal("notifyCurrentServerStatusIfReady() idle = false, want true for zero traffic rate")
	}
}

func TestNotifyCurrentServerStatusReturnsFalseWhenDRLNotReady(t *testing.T) {
	t.Parallel()

	gw := &Gateway{}

	if gw.NotifyCurrentServerStatus() {
		t.Fatal("NotifyCurrentServerStatus() = true with nil DRL manager, want false")
	}
	if gw.notifyCurrentServerStatusWithRate(1) {
		t.Fatal("notifyCurrentServerStatusWithRate() = true with nil DRL manager, want false")
	}
}

func TestMarkControlPlaneReadySetsReloadAndDRLGates(t *testing.T) {
	t.Parallel()

	gw := &Gateway{}
	gw.markControlPlaneReady()

	if !gw.performedSuccessfulReload {
		t.Fatal("markControlPlaneReady() did not set performedSuccessfulReload")
	}
	if !gw.controlPlaneReady.Load() {
		t.Fatal("markControlPlaneReady() did not set controlPlaneReady")
	}
}
