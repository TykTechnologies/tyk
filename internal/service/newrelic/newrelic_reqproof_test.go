package newrelic

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gocraft/health"
	"github.com/gorilla/mux"
	upstream "github.com/newrelic/go-agent/v3/newrelic"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

// Verifies: SYS-REQ-082, SW-REQ-067
// SW-REQ-067:nominal:nominal
// SW-REQ-067:boundary:nominal
// SW-REQ-067:error_handling:nominal
// SW-REQ-067:error_handling:negative
// SW-REQ-067:determinism:nominal
func TestNewRelicServiceHelpersPreserveObservabilityAdapterBehavior(t *testing.T) {
	t.Run("mount skips nil application and mounts configured application", func(t *testing.T) {
		router := mux.NewRouter()
		Mount(router, nil)

		called := false
		router.HandleFunc("/nil", func(w http.ResponseWriter, r *http.Request) {
			called = true
			require.Nil(t, FromContext(r.Context()))
			w.WriteHeader(http.StatusAccepted)
		})

		res := httptest.NewRecorder()
		router.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/nil", nil))
		require.True(t, called)
		require.Equal(t, http.StatusAccepted, res.Code)

		app, err := upstream.NewApplication(upstream.ConfigEnabled(false))
		require.NoError(t, err)

		router = mux.NewRouter()
		Mount(router, app)
		router.HandleFunc("/mounted", func(w http.ResponseWriter, r *http.Request) {
			require.NotNil(t, FromContext(r.Context()))
			w.WriteHeader(http.StatusCreated)
		})

		res = httptest.NewRecorder()
		router.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/mounted", nil))
		require.Equal(t, http.StatusCreated, res.Code)
	})

	t.Run("sink event names and parameters are deterministic", func(t *testing.T) {
		app, err := upstream.NewApplication(upstream.ConfigEnabled(false))
		require.NoError(t, err)

		sink := NewSink(app)
		require.Same(t, app, sink.relic)
		require.Equal(t, map[string]interface{}{"api": "pets", "status": "ok"}, makeParams(map[string]string{"api": "pets", "status": "ok"}))

		require.NotPanics(t, func() {
			sink.EmitEvent("job", "started", map[string]string{"api": "pets"})
			sink.EmitEventErr("job", "failed", errors.New("boom"), map[string]string{"api": "pets"})
			sink.EmitTiming("job", "latency", 42, map[string]string{"api": "pets"})
			sink.EmitComplete("job", health.Success, 99, map[string]string{"api": "pets"})
			sink.EmitGauge("job", "size", 2.5, map[string]string{"api": "pets"})
		})
	})

	t.Run("logger forwards levels fields and debug state", func(t *testing.T) {
		base, hook := logrustest.NewNullLogger()
		entry := base.WithField("component", "newrelic")
		logger := NewLogger(entry)

		require.False(t, logger.DebugEnabled())
		base.SetLevel(logrus.DebugLevel)
		logger.Level = logrus.DebugLevel
		require.True(t, logger.DebugEnabled())

		fields := map[string]interface{}{"key": "value"}
		logger.Error("error message", fields)
		logger.Warn("warn message", fields)
		logger.Info("info message", fields)
		logger.Debug("debug message", fields)

		require.Len(t, hook.Entries, 4)
		require.Equal(t, "error message", hook.Entries[0].Message)
		require.Equal(t, "warn message", hook.Entries[1].Message)
		require.Equal(t, "info message", hook.Entries[2].Message)
		require.Equal(t, "debug message", hook.Entries[3].Message)
		for _, got := range hook.Entries {
			require.Equal(t, "newrelic", got.Data["component"])
			require.Equal(t, "value", got.Data["key"])
		}
	})
}
