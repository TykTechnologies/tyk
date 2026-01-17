package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/certcheck"
	"github.com/TykTechnologies/tyk/internal/crypto"
)

// TestReverseProxy_initUpstreamCertBatcher tests lazy initialization of upstream cert batcher
func TestReverseProxy_initUpstreamCertBatcher(t *testing.T) {
	t.Run("should initialize batcher when upstream certs are configured", func(t *testing.T) {
		logger, _ := logrustest.NewNullLogger()

		ts := StartTest(nil)
		defer ts.Close()

		spec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "test-api"
			spec.Name = "Test API"
			spec.Proxy.ListenPath = "/test/"
			spec.UpstreamCertificates = map[string]string{
				"*.upstream.com": "cert-id-123",
			}
		})[0]

		ts.Gw.LoadAPI(spec)

		proxy := &ReverseProxy{
			TykAPISpec: spec,
			Gw:         ts.Gw,
			logger:     logrus.NewEntry(logger),
		}

		// Initialize the batcher
		proxy.initUpstreamCertBatcher()

		// Verify batcher was created
		assert.NotNil(t, spec.UpstreamCertExpiryBatcher, "Batcher should be initialized")
		assert.NotNil(t, spec.upstreamCertExpiryCheckContext, "Context should be created")
		assert.NotNil(t, spec.upstreamCertExpiryCancelFunc, "Cancel func should be created")

		// Cleanup
		if spec.upstreamCertExpiryCancelFunc != nil {
			spec.upstreamCertExpiryCancelFunc()
		}
	})

	t.Run("should not initialize when upstream certs are disabled", func(t *testing.T) {
		logger, _ := logrustest.NewNullLogger()

		ts := StartTest(nil)
		defer ts.Close()

		spec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "test-api"
			spec.Name = "Test API"
			spec.Proxy.ListenPath = "/test/"
			spec.UpstreamCertificatesDisabled = true
			spec.UpstreamCertificates = map[string]string{
				"*.upstream.com": "cert-id-123",
			}
		})[0]

		ts.Gw.LoadAPI(spec)

		proxy := &ReverseProxy{
			TykAPISpec: spec,
			Gw:         ts.Gw,
			logger:     logrus.NewEntry(logger),
		}

		// Initialize the batcher
		proxy.initUpstreamCertBatcher()

		// Verify batcher was NOT created
		assert.Nil(t, spec.UpstreamCertExpiryBatcher, "Batcher should not be initialized when disabled")
	})

	t.Run("should not initialize when no upstream certs are configured", func(t *testing.T) {
		logger, _ := logrustest.NewNullLogger()

		ts := StartTest(nil)
		defer ts.Close()

		spec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "test-api"
			spec.Name = "Test API"
			spec.Proxy.ListenPath = "/test/"
			// No upstream certificates
		})[0]

		ts.Gw.LoadAPI(spec)

		proxy := &ReverseProxy{
			TykAPISpec: spec,
			Gw:         ts.Gw,
			logger:     logrus.NewEntry(logger),
		}

		// Initialize the batcher
		proxy.initUpstreamCertBatcher()

		// Verify batcher was NOT created
		assert.Nil(t, spec.UpstreamCertExpiryBatcher, "Batcher should not be initialized when no certs configured")
	})

	t.Run("should initialize when global upstream certs are configured", func(t *testing.T) {
		logger, _ := logrustest.NewNullLogger()

		globalConf := config.Config{
			Security: config.SecurityConfig{
				Certificates: config.CertificatesConfig{
					Upstream: map[string]string{
						"*.global-upstream.com": "global-cert-id",
					},
				},
			},
		}

		ts := StartTest(func(c *config.Config) {
			*c = globalConf
		})
		defer ts.Close()

		spec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "test-api"
			spec.Name = "Test API"
			spec.Proxy.ListenPath = "/test/"
			// No API-specific certs, but global certs exist
		})[0]

		ts.Gw.LoadAPI(spec)

		proxy := &ReverseProxy{
			TykAPISpec: spec,
			Gw:         ts.Gw,
			logger:     logrus.NewEntry(logger),
		}

		// Initialize the batcher
		proxy.initUpstreamCertBatcher()

		// Verify batcher was created
		assert.NotNil(t, spec.UpstreamCertExpiryBatcher, "Batcher should be initialized with global certs")

		// Cleanup
		if spec.upstreamCertExpiryCancelFunc != nil {
			spec.upstreamCertExpiryCancelFunc()
		}
	})
}

// TestReverseProxy_checkUpstreamCertificateExpiry tests certificate expiry checking
func TestReverseProxy_checkUpstreamCertificateExpiry(t *testing.T) {
	t.Run("should trigger lazy initialization on first call", func(t *testing.T) {
		logger, _ := logrustest.NewNullLogger()

		ts := StartTest(nil)
		defer ts.Close()

		spec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "test-api"
			spec.Name = "Test API"
			spec.Proxy.ListenPath = "/test/"
			spec.UpstreamCertificates = map[string]string{
				"*.upstream.com": "cert-id-123",
			}
		})[0]

		ts.Gw.LoadAPI(spec)

		proxy := &ReverseProxy{
			TykAPISpec: spec,
			Gw:         ts.Gw,
			logger:     logrus.NewEntry(logger),
		}

		// Create a test certificate
		_, _, _, tlsCert := crypto.GenCertificate(&x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "test.upstream.com",
			},
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(48 * time.Hour),
		}, true)

		// Verify batcher not initialized yet
		assert.Nil(t, spec.UpstreamCertExpiryBatcher, "Batcher should not exist before first check")

		// Check certificate (should trigger lazy init)
		proxy.checkUpstreamCertificateExpiry(&tlsCert)

		// Verify batcher was initialized
		assert.NotNil(t, spec.UpstreamCertExpiryBatcher, "Batcher should be initialized after first check")

		// Cleanup
		if spec.upstreamCertExpiryCancelFunc != nil {
			spec.upstreamCertExpiryCancelFunc()
		}
	})

	t.Run("should only initialize once with sync.Once", func(t *testing.T) {
		logger, _ := logrustest.NewNullLogger()

		ts := StartTest(nil)
		defer ts.Close()

		spec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "test-api"
			spec.Name = "Test API"
			spec.Proxy.ListenPath = "/test/"
			spec.UpstreamCertificates = map[string]string{
				"*.upstream.com": "cert-id-123",
			}
		})[0]

		ts.Gw.LoadAPI(spec)

		proxy := &ReverseProxy{
			TykAPISpec: spec,
			Gw:         ts.Gw,
			logger:     logrus.NewEntry(logger),
		}

		// Create test certificates
		_, _, _, tlsCert1 := crypto.GenCertificate(&x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "test1.upstream.com",
			},
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(48 * time.Hour),
		}, true)

		_, _, _, tlsCert2 := crypto.GenCertificate(&x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject: pkix.Name{
				CommonName: "test2.upstream.com",
			},
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(24 * time.Hour),
		}, true)

		// Check multiple certificates concurrently
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(cert *tls.Certificate) {
				defer wg.Done()
				proxy.checkUpstreamCertificateExpiry(cert)
			}([]*tls.Certificate{&tlsCert1, &tlsCert2}[i%2])
		}
		wg.Wait()

		// Verify only one batcher was created
		assert.NotNil(t, spec.UpstreamCertExpiryBatcher, "Batcher should be initialized")

		// Cleanup
		if spec.upstreamCertExpiryCancelFunc != nil {
			spec.upstreamCertExpiryCancelFunc()
		}
	})

	t.Run("should skip when certificate is nil", func(t *testing.T) {
		logger, hook := logrustest.NewNullLogger()

		ts := StartTest(nil)
		defer ts.Close()

		spec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "test-api"
			spec.Name = "Test API"
			spec.Proxy.ListenPath = "/test/"
			spec.UpstreamCertificates = map[string]string{
				"*.upstream.com": "cert-id-123",
			}
		})[0]

		ts.Gw.LoadAPI(spec)

		proxy := &ReverseProxy{
			TykAPISpec: spec,
			Gw:         ts.Gw,
			logger:     logrus.NewEntry(logger),
		}

		// Trigger initialization first
		proxy.TykAPISpec.upstreamCertExpiryInitOnce.Do(proxy.initUpstreamCertBatcher)

		// Check nil certificate
		proxy.checkUpstreamCertificateExpiry(nil)

		// Verify warning was logged
		found := false
		for _, entry := range hook.Entries {
			if entry.Level == logrus.WarnLevel &&
				entry.Message == "Skipping upstream certificate expiry check: invalid certificate" {
				found = true
				break
			}
		}
		assert.True(t, found, "Should log warning for nil certificate")

		// Cleanup
		if spec.upstreamCertExpiryCancelFunc != nil {
			spec.upstreamCertExpiryCancelFunc()
		}
	})

	t.Run("should skip when certificate leaf is nil", func(t *testing.T) {
		logger, hook := logrustest.NewNullLogger()

		ts := StartTest(nil)
		defer ts.Close()

		spec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "test-api"
			spec.Name = "Test API"
			spec.Proxy.ListenPath = "/test/"
			spec.UpstreamCertificates = map[string]string{
				"*.upstream.com": "cert-id-123",
			}
		})[0]

		ts.Gw.LoadAPI(spec)

		proxy := &ReverseProxy{
			TykAPISpec: spec,
			Gw:         ts.Gw,
			logger:     logrus.NewEntry(logger),
		}

		// Trigger initialization first
		proxy.TykAPISpec.upstreamCertExpiryInitOnce.Do(proxy.initUpstreamCertBatcher)

		// Check certificate with nil leaf
		certWithoutLeaf := &tls.Certificate{
			Certificate: [][]byte{[]byte("fake-cert-data")},
			Leaf:        nil,
		}
		proxy.checkUpstreamCertificateExpiry(certWithoutLeaf)

		// Verify warning was logged
		found := false
		for _, entry := range hook.Entries {
			if entry.Level == logrus.WarnLevel &&
				entry.Message == "Skipping upstream certificate expiry check: invalid certificate" {
				found = true
				break
			}
		}
		assert.True(t, found, "Should log warning for certificate without leaf")

		// Cleanup
		if spec.upstreamCertExpiryCancelFunc != nil {
			spec.upstreamCertExpiryCancelFunc()
		}
	})

	t.Run("should add certificate to batcher", func(t *testing.T) {
		logger, _ := logrustest.NewNullLogger()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBatcher := certcheck.NewMockBackgroundBatcher(ctrl)

		ts := StartTest(nil)
		defer ts.Close()

		spec := BuildAPI(func(spec *APISpec) {
			spec.APIID = "test-api"
			spec.Name = "Test API"
			spec.Proxy.ListenPath = "/test/"
			spec.UpstreamCertificates = map[string]string{
				"*.upstream.com": "cert-id-123",
			}
		})[0]

		// Inject mock batcher
		spec.UpstreamCertExpiryBatcher = mockBatcher
		spec.upstreamCertExpiryCheckContext = context.Background()
		spec.upstreamCertExpiryCancelFunc = func() {}

		ts.Gw.LoadAPI(spec)

		proxy := &ReverseProxy{
			TykAPISpec: spec,
			Gw:         ts.Gw,
			logger:     logrus.NewEntry(logger),
		}

		// Create test certificate
		_, _, _, tlsCert := crypto.GenCertificate(&x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "test.upstream.com",
			},
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(48 * time.Hour),
		}, true)

		certID := crypto.HexSHA256(tlsCert.Leaf.Raw)

		// Expect Add to be called with correct CertInfo
		mockBatcher.EXPECT().Add(gomock.Any()).DoAndReturn(func(certInfo certcheck.CertInfo) error {
			assert.Equal(t, certID, certInfo.ID, "Certificate ID should match")
			assert.Equal(t, "test.upstream.com", certInfo.CommonName, "Common name should match")
			assert.Equal(t, tlsCert.Leaf.NotAfter, certInfo.NotAfter, "NotAfter should match")
			assert.True(t, certInfo.UntilExpiry > 0, "UntilExpiry should be positive")
			return nil
		})

		// Check certificate
		proxy.checkUpstreamCertificateExpiry(&tlsCert)
	})
}
