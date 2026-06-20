package gateway

import (
	"net/http"
	"testing"

	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/test"
)

// Verifies: STK-REQ-050, SYS-REQ-138, SW-REQ-125
// STK-REQ-050:STK-REQ-050-AC-07:acceptance
// SYS-REQ-138:nominal:nominal
// SYS-REQ-138:error_handling:negative
// SW-REQ-125:nominal:nominal
// SW-REQ-125:error_handling:negative
func TestGoAnalyticsPlugin_LoadAnalyticsPlugin(t *testing.T) {
	testCases := []struct {
		name       string
		plugin     GoAnalyticsPlugin
		wantLoaded bool
	}{
		{
			name: "already initialized",
			plugin: GoAnalyticsPlugin{
				Path:     "already-loaded.so",
				FuncName: "HandleAnalytics",
				handler:  func(record *analytics.AnalyticsRecord) {},
			},
			wantLoaded: true,
		},
		{
			name: "loader failure",
			plugin: GoAnalyticsPlugin{
				Path:     "",
				FuncName: "",
			},
			wantLoaded: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			loaded := tc.plugin.loadAnalyticsPlugin()

			assert.Equal(t, tc.wantLoaded, loaded)
			assert.NotNil(t, tc.plugin.logger)
		})
	}
}

// Verifies: STK-REQ-050, SYS-REQ-138, SW-REQ-125
// STK-REQ-050:STK-REQ-050-AC-07:acceptance
// SYS-REQ-138:nominal:nominal
// SYS-REQ-138:error_handling:negative
// SW-REQ-125:nominal:nominal
// SW-REQ-125:error_handling:negative
func TestGoAnalyticsPlugin_ProcessRecord(t *testing.T) {
	nullLogger, _ := logrustest.NewNullLogger()

	t.Run("nil plugin", func(t *testing.T) {
		var plugin *GoAnalyticsPlugin

		err := plugin.processRecord(&analytics.AnalyticsRecord{})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "nil value")
	})

	t.Run("invokes handler", func(t *testing.T) {
		record := &analytics.AnalyticsRecord{Path: "/before"}
		plugin := &GoAnalyticsPlugin{
			logger: nullLogger.WithField("test", t.Name()),
			handler: func(record *analytics.AnalyticsRecord) {
				record.Path = "/after"
			},
		}

		err := plugin.processRecord(record)

		require.NoError(t, err)
		assert.Equal(t, "/after", record.Path)
	})

	t.Run("recovers handler panic", func(t *testing.T) {
		plugin := &GoAnalyticsPlugin{
			logger: nullLogger.WithField("test", t.Name()),
			handler: func(record *analytics.AnalyticsRecord) {
				panic("analytics plugin panic")
			},
		}

		err := plugin.processRecord(&analytics.AnalyticsRecord{})

		require.Error(t, err)
	})
}

// Verifies: STK-REQ-050, SYS-REQ-138, SW-REQ-125
// STK-REQ-050:STK-REQ-050-AC-07:acceptance
// SYS-REQ-138:error_handling:nominal
// SW-REQ-125:error_handling:nominal
func TestGoAnalyticsPlugin(t *testing.T) {
	g := StartTest(nil)
	defer g.Close()

	t.Run("just enabled without other parameters set", func(t *testing.T) {
		g.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			spec.AnalyticsPlugin.Enabled = true
		})

		_, _ = g.Run(t, test.TestCase{Path: "/", Code: http.StatusOK})
	})
}
