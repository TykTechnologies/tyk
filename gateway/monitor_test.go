package gateway

import (
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"
	"github.com/stretchr/testify/assert"
)

func TestMonitor_checkLimit(t *testing.T) {
	gw := &Gateway{}
	gw.SetConfig(config.Config{
		Monitor: config.MonitorConfig{
			GlobalTriggerLimit: 80.0,
		},
	})
	m := Monitor{Gw: gw}

	sessionData := &user.SessionState{
		OrgID: "test-org",
	}

	key := "test-key"

	// Test case 1: Quota renewal rate > 0 and renewal date in the past
	// Should skip and return false
	quotaMax := int64(100)
	quotaRemaining := int64(10) // 90% used
	quotaRenews := time.Now().Add(-1 * time.Hour).Unix()
	quotaRenewalRate := int64(3600)

	result := m.checkLimit(sessionData, key, quotaMax, quotaRemaining, quotaRenews, quotaRenewalRate)
	assert.False(t, result, "Should return false when renewal date is in the past and quotaRenewalRate > 0")

	// Test case 2: Quota renewal rate <= 0 and renewal date in the past
	// Should NOT skip, and should fire because usage is 90% (>= 80%)
	quotaRenewalRate = int64(0)
	gw.MonitoringHandler = &dummyMonitoringHandler{}

	result = m.checkLimit(sessionData, key, quotaMax, quotaRemaining, quotaRenews, quotaRenewalRate)
	assert.True(t, result, "Should return true and fire when quotaRenewalRate <= 0 even if renewal date is in the past")

	// Test case 3: Quota renewal rate > 0 and renewal date in the future
	// Should NOT skip, and should fire because usage is 90% (>= 80%)
	quotaRenews = time.Now().Add(1 * time.Hour).Unix()
	quotaRenewalRate = int64(3600)

	result = m.checkLimit(sessionData, key, quotaMax, quotaRemaining, quotaRenews, quotaRenewalRate)
	assert.True(t, result, "Should return true and fire when renewal date is in the future")
}

type dummyMonitoringHandler struct{}

func (d *dummyMonitoringHandler) Init(interface{}) error             { return nil }
func (d *dummyMonitoringHandler) HandleEvent(em config.EventMessage) {}
func (d *dummyMonitoringHandler) UpdateConfig(conf *config.Config)   {}
