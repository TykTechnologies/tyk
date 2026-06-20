package checkup

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
)

// Verifies: STK-REQ-024, SYS-REQ-112, SW-REQ-099
// STK-REQ-024:STK-REQ-024-AC-01:acceptance
// STK-REQ-024:STK-REQ-024-AC-02:acceptance
// STK-REQ-024:STK-REQ-024-AC-03:acceptance
// SYS-REQ-112:nominal:nominal
// SW-REQ-099:nominal:nominal
// SW-REQ-099:boundary:nominal
// SW-REQ-099:error_handling:nominal
// SW-REQ-099:error_handling:negative
// STK-REQ-024:error_handling:negative
// MCDC SYS-REQ-112: startup_checkup_requested=F, startup_checkup_result_determined=F => TRUE
// MCDC SYS-REQ-112: startup_checkup_requested=T, startup_checkup_result_determined=T => TRUE
//
//mcdc:ignore SYS-REQ-112: startup_checkup_requested=T, startup_checkup_result_determined=F => FALSE -- violation row is the negation of the startup checkup result guarantee; this test asserts requested checkup paths either emit diagnostics, preserve safe values, or apply deterministic analytics defaults [category: defensive] [reviewed: agent:codex]
func TestCheckupPreservesStartupConfigurationDiagnostics(t *testing.T) {
	t.Run("warning helpers emit diagnostics for configured startup risks", func(t *testing.T) {
		tests := []struct {
			name      string
			configure func(*config.Config)
			run       func(*config.Config)
			want      []string
		}{
			{
				name: "insecure configs allowed",
				configure: func(c *config.Config) {
					c.AllowInsecureConfigs = true
				},
				run:  allowInsecureConfigs,
				want: []string{"Insecure configuration allowed", "config.allow_insecure_configs=true"},
			},
			{
				name: "deprecated health checks enabled",
				configure: func(c *config.Config) {
					c.HealthCheck.EnableHealthChecks = true
				},
				run:  healthCheck,
				want: []string{"Health Checker is deprecated and not recommended"},
			},
			{
				name: "session lifetime unset",
				configure: func(c *config.Config) {
					c.GlobalSessionLifetime = 0
				},
				run:  sessionLifetimeCheck,
				want: []string{"Tyk has not detected any setting for session lifetime"},
			},
			{
				name: "default secrets retained",
				configure: func(c *config.Config) {
					c.Secret = defaultConfigs.Secret
					c.NodeSecret = defaultConfigs.NodeSecret
				},
				run: defaultSecrets,
				want: []string{
					"Default secret should be changed for production.",
					"Default node_secret should be changed for production.",
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				out := captureCheckupLogs(t)
				cfg := &config.Config{}
				tt.configure(cfg)

				tt.run(cfg)

				for _, want := range tt.want {
					assert.Contains(t, out.String(), want)
				}
			})
		}
	})

	t.Run("analytics defaults are applied only when analytics is enabled", func(t *testing.T) {
		tests := []struct {
			name           string
			cfg            config.Config
			wantPool       int
			wantBufferSize uint64
			wantExpiration int
		}{
			{
				name:           "analytics disabled preserves zero values",
				cfg:            config.Config{},
				wantPool:       0,
				wantBufferSize: 0,
				wantExpiration: 0,
			},
			{
				name: "analytics enabled fills zero defaults",
				cfg: config.Config{
					EnableAnalytics: true,
				},
				wantPool:       runtime.NumCPU(),
				wantBufferSize: minRecordsBufferSize,
				wantExpiration: 60,
			},
			{
				name: "analytics enabled preserves sufficient values",
				cfg: config.Config{
					EnableAnalytics: true,
					AnalyticsConfig: config.AnalyticsConfigConfig{
						PoolSize:              7,
						RecordsBufferSize:     minRecordsBufferSize + 1,
						StorageExpirationTime: 90,
					},
				},
				wantPool:       7,
				wantBufferSize: minRecordsBufferSize + 1,
				wantExpiration: 90,
			},
			{
				name: "analytics enabled raises undersized records buffer",
				cfg: config.Config{
					EnableAnalytics: true,
					AnalyticsConfig: config.AnalyticsConfigConfig{
						PoolSize:              3,
						RecordsBufferSize:     minRecordsBufferSize - 1,
						StorageExpirationTime: 30,
					},
				},
				wantPool:       3,
				wantBufferSize: minRecordsBufferSize,
				wantExpiration: 30,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				out := captureCheckupLogs(t)
				cfg := tt.cfg

				defaultAnalytics(&cfg)

				assert.Equal(t, tt.wantPool, cfg.AnalyticsConfig.PoolSize)
				assert.Equal(t, tt.wantBufferSize, cfg.AnalyticsConfig.RecordsBufferSize)
				assert.Equal(t, tt.wantExpiration, cfg.AnalyticsConfig.StorageExpirationTime)
				if !cfg.EnableAnalytics {
					assert.Empty(t, out.String())
				}
			})
		}
	})

	t.Run("run orchestrates warnings and deterministic analytics defaults", func(t *testing.T) {
		out := captureCheckupLogs(t)
		cfg := &config.Config{
			AllowInsecureConfigs: true,
			Secret:               defaultConfigs.Secret,
			NodeSecret:           defaultConfigs.NodeSecret,
			EnableAnalytics:      true,
			HealthCheck: config.HealthCheckConfig{
				EnableHealthChecks: true,
			},
		}

		Run(cfg)

		assert.Equal(t, runtime.NumCPU(), cfg.AnalyticsConfig.PoolSize)
		assert.Equal(t, uint64(minRecordsBufferSize), cfg.AnalyticsConfig.RecordsBufferSize)
		assert.Equal(t, 60, cfg.AnalyticsConfig.StorageExpirationTime)
		for _, want := range []string{
			"Insecure configuration allowed",
			"Health Checker is deprecated and not recommended",
			"Tyk has not detected any setting for session lifetime",
			"Default secret should be changed for production.",
			"Default node_secret should be changed for production.",
			"AnalyticsConfig.PoolSize unset",
			"AnalyticsConfig.RecordsBufferSize < minimum",
			"AnalyticsConfig.StorageExpirationTime is 0",
		} {
			assert.Contains(t, out.String(), want)
		}
	})

	t.Run("host resource probes execute without mutating gateway config", func(t *testing.T) {
		assert.NotPanics(t, fileDescriptors)
		assert.NotPanics(t, cpus)
	})
}

func captureCheckupLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	var out bytes.Buffer
	logger := log.Logger
	previousOut := logger.Out
	previousFormatter := logger.Formatter
	previousLevel := logger.Level

	logger.SetOutput(&out)
	logger.SetFormatter(&logrus.TextFormatter{
		DisableColors:    true,
		DisableTimestamp: true,
		DisableQuote:     true,
	})
	logger.SetLevel(logrus.WarnLevel)

	t.Cleanup(func() {
		logger.SetOutput(previousOut)
		logger.SetFormatter(previousFormatter)
		logger.SetLevel(previousLevel)
	})

	return &out
}
