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
		heartBeatStopSentinel: HeartBeatStarted,
	}
	assert.False(t, handler.isHeartBeatStopped())

	handler = HTTPDashboardHandler{
		heartBeatStopSentinel: HeartBeatStopped,
	}

	assert.True(t, handler.isHeartBeatStopped())

	handler = HTTPDashboardHandler{
		heartBeatStopSentinel: HeartBeatStarted,
	}

	handler.StopBeating()
	assert.True(t, handler.isHeartBeatStopped())
}
