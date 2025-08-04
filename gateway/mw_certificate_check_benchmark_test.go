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

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs/mock"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/TykTechnologies/tyk/storage"
	"go.uber.org/mock/gomock"
)

// newBenchmarkCertificateCheckMW creates a middleware instance for benchmarking
func newBenchmarkCertificateCheckMW(b *testing.B, useMutualTLS bool, certs []*tls.Certificate) *CertificateCheckMW {
	ctrl := gomock.NewController(b)
	mockCertManager := mock.NewMockCertificateManager(ctrl)

	if certs != nil {
		mockCertManager.EXPECT().
			List(gomock.Any(), gomock.Any()).
			Return(certs).
			AnyTimes()
	}

	// Create a cache for testing
	mockCache := cache.New(3600, 600)

	// Generate unique test prefix for Redis keys to avoid clashes
	testPrefix := fmt.Sprintf("benchmark-%d-", time.Now().UnixNano())

	gw := &Gateway{
		CertificateManager: mockCertManager,
		UtilCache:          mockCache,
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

	return mw
}

// createTestCertificate creates a test certificate with specified expiration
func createTestCertificate(daysUntilExpiry int) *tls.Certificate {
	expirationDate := time.Now().Add(time.Duration(daysUntilExpiry) * 24 * time.Hour)
	return &tls.Certificate{
		Leaf: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "test.example.com",
			},
			NotAfter: expirationDate,
			Raw:      []byte("test-certificate-data"),
			Extensions: []pkix.Extension{
				{Value: []byte("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")},
			},
		},
	}
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

// BenchmarkCertificateCheckMW_NoMutualTLS benchmarks the middleware when mutual TLS is disabled
func BenchmarkCertificateCheckMW_NoMutualTLS(b *testing.B) {
	mw := newBenchmarkCertificateCheckMW(b, false, nil)
	req := createTestRequest(false, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mw.ProcessRequest(nil, req, nil)
	}
}

// BenchmarkCertificateCheckMW_ValidCertificate benchmarks the middleware with valid certificates
func BenchmarkCertificateCheckMW_ValidCertificate(b *testing.B) {
	validCert := createTestCertificate(60) // 60 days until expiry
	mw := newBenchmarkCertificateCheckMW(b, true, []*tls.Certificate{validCert})

	peerCert := &x509.Certificate{
		Raw:        []byte("abc"),
		NotAfter:   time.Now().Add(time.Hour),
		Extensions: []pkix.Extension{{Value: []byte("dummy")}},
	}
	req := createTestRequest(true, []*x509.Certificate{peerCert})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mw.ProcessRequest(nil, req, nil)
	}
}

// BenchmarkCertificateCheckMW_ExpiringCertificate benchmarks the middleware with expiring certificates
func BenchmarkCertificateCheckMW_ExpiringCertificate(b *testing.B) {
	expiringCert := createTestCertificate(15) // 15 days until expiry (within threshold)
	mw := newBenchmarkCertificateCheckMW(b, true, []*tls.Certificate{expiringCert})

	peerCert := &x509.Certificate{
		Raw:        []byte("abc"),
		NotAfter:   time.Now().Add(time.Hour),
		Extensions: []pkix.Extension{{Value: []byte("dummy")}},
	}
	req := createTestRequest(true, []*x509.Certificate{peerCert})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mw.ProcessRequest(nil, req, nil)
	}
}

// BenchmarkCertificateCheckMW_MultipleCertificates benchmarks the middleware with multiple certificates
func BenchmarkCertificateCheckMW_MultipleCertificates(b *testing.B) {
	certs := []*tls.Certificate{
		createTestCertificate(60), // Valid
		createTestCertificate(15), // Expiring
		createTestCertificate(5),  // Critical
		createTestCertificate(90), // Valid
	}
	mw := newBenchmarkCertificateCheckMW(b, true, certs)

	peerCert := &x509.Certificate{
		Raw:        []byte("abc"),
		NotAfter:   time.Now().Add(time.Hour),
		Extensions: []pkix.Extension{{Value: []byte("dummy")}},
	}
	req := createTestRequest(true, []*x509.Certificate{peerCert})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mw.ProcessRequest(nil, req, nil)
	}
}

// BenchmarkCertificateCheckMW_HelperMethods benchmarks the helper methods
func BenchmarkCertificateCheckMW_HelperMethods(b *testing.B) {
	mw := newBenchmarkCertificateCheckMW(b, true, nil)
	cert := createTestCertificate(30)

	b.Run("GenerateCertificateID", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = mw.generateCertificateID(cert)
		}
	})

	b.Run("ShouldFireEvent", func(b *testing.B) {
		config := mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor
		for i := 0; i < b.N; i++ {
			_ = mw.shouldFireExpiryEvent("test-cert-id", config)
		}
	})

	b.Run("FireCertificateExpiringSoonEvent", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			mw.fireCertificateExpiringSoonEvent(cert, 30)
		}
	})
}

// BenchmarkCertificateCheckMW_CheckCertificateExpiration benchmarks the certificate expiration checking logic
func BenchmarkCertificateCheckMW_CheckCertificateExpiration(b *testing.B) {
	mw := newBenchmarkCertificateCheckMW(b, true, nil)

	b.Run("NoExpiringCertificates", func(b *testing.B) {
		certs := []*tls.Certificate{
			createTestCertificate(60),
			createTestCertificate(90),
			createTestCertificate(120),
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mw.checkCertificateExpiration(certs)
		}
	})

	b.Run("WithExpiringCertificates", func(b *testing.B) {
		certs := []*tls.Certificate{
			createTestCertificate(60),
			createTestCertificate(15), // Expiring
			createTestCertificate(5),  // Critical
			createTestCertificate(90),
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mw.checkCertificateExpiration(certs)
		}
	})

	b.Run("MixedCertificates", func(b *testing.B) {
		certs := []*tls.Certificate{
			createTestCertificate(60),
			createTestCertificate(15), // Expiring
			createTestCertificate(90),
			createTestCertificate(3), // Critical
			createTestCertificate(45),
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mw.checkCertificateExpiration(certs)
		}
	})
}

// BenchmarkCertificateCheckMW_CacheOperations benchmarks Redis cache operations
func BenchmarkCertificateCheckMW_CacheOperations(b *testing.B) {
	mw := newBenchmarkCertificateCheckMW(b, true, nil)
	monitorConfig := mw.Spec.GlobalConfig.Security.CertificateExpiryMonitor

	b.Run("CacheGet", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = mw.Gw.UtilCache.Get("test-key")
		}
	})

	b.Run("CacheSet", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			mw.Gw.UtilCache.Set("test-key", "test-value", 3600)
		}
	})

	b.Run("ShouldFireEventWithCache", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			certID := "benchmark-cert-id"
			_ = mw.shouldFireExpiryEvent(certID, monitorConfig)
		}
	})
}

// BenchmarkCertificateCheckMW_EventFiring benchmarks event firing performance
func BenchmarkCertificateCheckMW_EventFiring(b *testing.B) {
	mw := newBenchmarkCertificateCheckMW(b, true, nil)
	cert := createTestCertificate(15)

	b.Run("EventFiringOnly", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			mw.fireCertificateExpiringSoonEvent(cert, 15)
		}
	})

	b.Run("FullExpirationCheck", func(b *testing.B) {
		certs := []*tls.Certificate{cert}
		for i := 0; i < b.N; i++ {
			mw.checkCertificateExpiration(certs)
		}
	})
}

// BenchmarkCertificateCheckMW_MemoryUsage benchmarks memory usage patterns
func BenchmarkCertificateCheckMW_MemoryUsage(b *testing.B) {
	mw := newBenchmarkCertificateCheckMW(b, true, nil)
	cert := createTestCertificate(15)

	b.Run("CertificateIDGeneration", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = mw.generateCertificateID(cert)
		}
	})

	b.Run("EventMetadataCreation", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			mw.fireCertificateExpiringSoonEvent(cert, 15)
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
