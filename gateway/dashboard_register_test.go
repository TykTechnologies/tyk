package gateway

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
)

func Test_BuildDashboardConnStr(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.DisableDashboardZeroConf = false
		globalConf.DBAppConfOptions.ConnectionString = ""
	})
	defer ts.Close()

	//we trigger a go routine here to simulate a redis zeroconf
	go func() {
		time.Sleep(1 * time.Second)
		cfg := ts.Gw.GetConfig()
		cfg.DBAppConfOptions.ConnectionString = "http://localhost"
		ts.Gw.SetConfig(cfg)
	}()

	connStr := ts.Gw.buildDashboardConnStr("/test")

	assert.Equal(t, connStr, "http://localhost/test")
}

func Test_DashboardLifecycle(t *testing.T) {
	var handler HTTPDashboardHandler

	handler = HTTPDashboardHandler{
		heartBeatStopSentinel: STARTED,
	}
	assert.False(t, handler.isStopped())

	handler = HTTPDashboardHandler{
		heartBeatStopSentinel: STOPPED,
	}

	assert.True(t, handler.isStopped())

	handler = HTTPDashboardHandler{
		heartBeatStopSentinel: STARTED,
	}

	handler.StopBeating()
	assert.True(t, handler.isStopped())
}
