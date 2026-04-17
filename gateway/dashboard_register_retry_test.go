package gateway

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNextRegisterRetryDelay(t *testing.T) {
	testCases := []struct {
		name    string
		attempt int
		min     time.Duration
		max     time.Duration
	}{
		{name: "attempt1", attempt: 1, min: 5 * time.Second, max: 6500 * time.Millisecond},
		{name: "attempt2", attempt: 2, min: 10 * time.Second, max: 11500 * time.Millisecond},
		{name: "attempt5_cap", attempt: 5, min: 60 * time.Second, max: 60 * time.Second},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &HTTPDashboardHandler{retryRng: rand.New(rand.NewSource(1))}
			delay := h.nextRegisterRetryDelay(tc.attempt)
			assert.GreaterOrEqual(t, delay, tc.min)
			assert.LessOrEqual(t, delay, tc.max)
		})
	}
}

func TestForbiddenRecoveryPlan_ResetAndMetric(t *testing.T) {
	now := time.Unix(1700000000, 0)
	h := &HTTPDashboardHandler{
		Gw:       &Gateway{},
		now:      func() time.Time { return now },
		retryRng: rand.New(rand.NewSource(42)),
	}
	h.Gw.SetNodeID("node-1")

	originalMetricRecorder := recordReRegisterCircuitOpenMetric
	t.Cleanup(func() {
		recordReRegisterCircuitOpenMetric = originalMetricRecorder
	})

	var metricCalls int
	var metricNodeID string
	var metricConsecutive int
	var metricDelay time.Duration
	recordReRegisterCircuitOpenMetric = func(nodeID string, consecutive int, delay time.Duration) {
		metricCalls++
		metricNodeID = nodeID
		metricConsecutive = consecutive
		metricDelay = delay
	}

	firstDelay, firstConsecutive := h.nextForbiddenRecoveryPlan()
	require.Equal(t, 1, firstConsecutive)
	assert.GreaterOrEqual(t, firstDelay, time.Second)
	assert.LessOrEqual(t, firstDelay, 5*time.Second)

	h.recordReRegisterCircuitOpen(firstConsecutive, firstDelay)
	assert.Equal(t, 0, metricCalls)

	now = now.Add(10 * time.Second)
	secondDelay, secondConsecutive := h.nextForbiddenRecoveryPlan()
	require.Equal(t, 2, secondConsecutive)
	assert.GreaterOrEqual(t, secondDelay, 2*time.Second)
	assert.LessOrEqual(t, secondDelay, 60*time.Second)

	h.recordReRegisterCircuitOpen(secondConsecutive, secondDelay)
	require.Equal(t, 1, metricCalls)
	assert.Equal(t, "node-1", metricNodeID)
	assert.Equal(t, 2, metricConsecutive)
	assert.Equal(t, secondDelay, metricDelay)

	h.resetForbiddenRecoveryState()
	now = now.Add(time.Second)
	_, consecutiveAfterReset := h.nextForbiddenRecoveryPlan()
	assert.Equal(t, 1, consecutiveAfterReset)
}

func TestSleepWithContext(t *testing.T) {
	t.Run("cancelled_context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := sleepWithContext(ctx, 5*time.Second)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("non_positive_delay", func(t *testing.T) {
		err := sleepWithContext(context.Background(), 0)
		require.NoError(t, err)

		err = sleepWithContext(context.Background(), -1*time.Second)
		require.NoError(t, err)
	})
}
