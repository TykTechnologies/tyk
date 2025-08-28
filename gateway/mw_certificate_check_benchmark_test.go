package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs/mock"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/certcheck"
	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/storage"
)

// setupCertificateCheckMWBenchmark creates a middleware instance for benchmarking
func setupCertificateCheckMWBenchmark(b *testing.B, useMutualTLS bool, certs []*tls.Certificate) *CertificateCheckMW {
	ctrl := gomock.NewController(b)
	mockCertManager := mock.NewMockCertificateManager(ctrl)

	if certs != nil {
		mockCertManager.EXPECT().
			List(gomock.Any(), gomock.Any()).
			Return(certs).
			AnyTimes()
	}

	// Generate unique test prefix for Redis keys to avoid clashes
	testPrefix := fmt.Sprintf("benchmark-%d-", time.Now().UnixNano())

	gw := &Gateway{
		CertificateManager: mockCertManager,
	}

	// Initialize storage connection handler
	gw.StorageConnectionHandler = storage.NewConnectionHandler(context.Background())

	// Set the configuration properly with Redis storage
	gwConfig := config.Config{
		Storage: config.StorageOptionsConf{
			Type:    "redis",
			Host:    "localhost",
			Port:    6379,
			MaxIdle: 100,
		},
		Security: config.SecurityConfig{
			Certificates: config.CertificatesConfig{
				API: []string{"cert2"},
			},
			CertificateExpiryMonitor: config.CertificateExpiryMonitorConfig{
				WarningThresholdDays: 30,
				CheckCooldownSeconds: 3600,
				EventCooldownSeconds: 86400,
			},
		},
	}
	gw.SetConfig(gwConfig)

	// Connect to Redis
	ctx := context.Background()
	gw.StorageConnectionHandler.Connect(ctx, func() {
		// Connection callback - do nothing for benchmarks
	}, &gwConfig)

	// Wait for connection to be established
	timeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connected := gw.StorageConnectionHandler.WaitConnect(timeout)
	if !connected {
		b.Fatalf("Redis connection was not established in benchmark setup")
	}

	mw := &CertificateCheckMW{
		BaseMiddleware: &BaseMiddleware{
			Spec: &APISpec{
				APIDefinition: &apidef.APIDefinition{
					UseMutualTLSAuth:   useMutualTLS,
					ClientCertificates: []string{"cert1"},
					APIID:              "benchmark-test-api-id",
					OrgID:              "benchmark-test-org-id",
				},
				GlobalConfig: gw.GetConfig(),
			},
			Gw: gw,
		},
	}

	// Initialize Redis store with randomized prefix
	mw.store = &storage.RedisCluster{
		KeyPrefix:         fmt.Sprintf("cert-cooldown:%s", testPrefix),
		ConnectionHandler: gw.StorageConnectionHandler,
	}
	mw.store.Connect()

	logger, _ := logrustest.NewNullLogger()
	mw.expiryCheckBatcher, _ = certcheck.NewCertificateExpiryCheckBatcher(
		logrus.NewEntry(logger),
		mw.Gw.GetConfig().Security.CertificateExpiryMonitor,
		mw.store,
		mw.Spec.FireEvent)

	mw.expiryCheckBatcher.SetFlushInterval(10 * time.Millisecond)

	return mw
}

// createTestRequest creates a test HTTP request with optional TLS
func createTestRequest(withTLS bool, peerCerts []*x509.Certificate) *http.Request {
	req := &http.Request{}
	if withTLS {
		req.TLS = &tls.ConnectionState{
			PeerCertificates: peerCerts,
		}
	}
	return req
}

// BenchmarkCertificateCheckMW_ProcessRequest benchmarks the main ProcessRequest method
func BenchmarkCertificateCheckMW_ProcessRequest(b *testing.B) {
	tests := []struct {
		name         string
		useMutualTLS bool
		certs        []*tls.Certificate
		withTLS      bool
		peerCerts    []*x509.Certificate
	}{
		{"NoMutualTLS", false, nil, false, nil},
		{"ValidCertificate", true, []*tls.Certificate{createTestCertificate(60, "benchmark-cert")}, true, []*x509.Certificate{{
			Raw:        []byte("abc"),
			NotAfter:   time.Now().Add(time.Hour),
			Extensions: []pkix.Extension{{Value: []byte("dummy")}},
		}}},
		{"ExpiringCertificate", true, []*tls.Certificate{createTestCertificate(15, "benchmark-cert")}, true, []*x509.Certificate{{
			Raw:        []byte("abc"),
			NotAfter:   time.Now().Add(time.Hour),
			Extensions: []pkix.Extension{{Value: []byte("dummy")}},
		}}},
		{"MultipleCertificates", true, []*tls.Certificate{
			createTestCertificate(60, "benchmark-cert"),
			createTestCertificate(15, "benchmark-cert"),
			createTestCertificate(5, "benchmark-cert"),
			createTestCertificate(90, "benchmark-cert"),
		}, true, []*x509.Certificate{{
			Raw:        []byte("abc"),
			NotAfter:   time.Now().Add(time.Hour),
			Extensions: []pkix.Extension{{Value: []byte("dummy")}},
		}}},
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	for _, tc := range tests {
		b.Run(tc.name, func(b *testing.B) {
			mw := setupCertificateCheckMWBenchmark(b, tc.useMutualTLS, tc.certs)
			go mw.expiryCheckBatcher.RunInBackground(ctx)
			req := createTestRequest(tc.withTLS, tc.peerCerts)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = mw.ProcessRequest(nil, req, nil)
			}
		})
	}
}

// BenchmarkCertificateCheckMW_CheckCertificateExpiration benchmarks the certificate expiration checking logic
func BenchmarkCertificateCheckMW_CheckCertificateExpiration(b *testing.B) {
	mw := setupCertificateCheckMWBenchmark(b, true, nil)
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	go mw.expiryCheckBatcher.RunInBackground(ctx)

	tests := []struct {
		name  string
		certs []*tls.Certificate
	}{
		{"NoExpiringCertificates", []*tls.Certificate{
			createTestCertificate(60, "benchmark-cert"),
			createTestCertificate(90, "benchmark-cert"),
			createTestCertificate(120, "benchmark-cert"),
		}},
		{"WithExpiringCertificates", []*tls.Certificate{
			createTestCertificate(60, "benchmark-cert"),
			createTestCertificate(15, "benchmark-cert"),
			createTestCertificate(5, "benchmark-cert"),
			createTestCertificate(90, "benchmark-cert"),
		}},
		{"MixedCertificates", []*tls.Certificate{
			createTestCertificate(60, "benchmark-cert"),
			createTestCertificate(15, "benchmark-cert"),
			createTestCertificate(90, "benchmark-cert"),
			createTestCertificate(3, "benchmark-cert"),
			createTestCertificate(45, "benchmark-cert"),
		}},
	}

	for _, tc := range tests {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				mw.batchCertificatesExpiration(tc.certs)
			}
		})
	}
}

// BenchmarkCertificateCheckMW_MemoryUsage benchmarks memory usage patterns
func BenchmarkCertificateCheckMW_MemoryUsage(b *testing.B) {
	mw := setupCertificateCheckMWBenchmark(b, true, nil)
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	go mw.expiryCheckBatcher.RunInBackground(ctx)
	cert := createTestCertificate(15, "benchmark-cert")

	b.Run("CertificateIDGeneration", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = crypto.HexSHA256(cert.Leaf.Raw)
		}
	})

	b.Run("FullProcessRequest", func(b *testing.B) {
		b.ReportAllocs()
		// Create a new middleware with proper mock setup for this test
		ctrl := gomock.NewController(b)
		mockCertManager := mock.NewMockCertificateManager(ctrl)
		mockCertManager.EXPECT().
			List(gomock.Any(), gomock.Any()).
			Return([]*tls.Certificate{cert}).
			AnyTimes()

		mw.Gw.CertificateManager = mockCertManager

		req := createTestRequest(true, []*x509.Certificate{{
			Raw:        []byte("abc"),
			NotAfter:   time.Now().Add(time.Hour),
			Extensions: []pkix.Extension{{Value: []byte("dummy")}},
		}})
		for i := 0; i < b.N; i++ {
			_, _ = mw.ProcessRequest(nil, req, nil)
		}
	})
}
