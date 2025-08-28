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
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs/mock"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/certcheck"
	"github.com/TykTechnologies/tyk/storage"
	mockstorage "github.com/TykTechnologies/tyk/storage/mock"
)

// createTestCertificate creates a test certificate with specified expiration and common name
func createTestCertificate(daysUntilExpiry int, commonName string) *tls.Certificate {
	expirationDate := time.Now().Add(time.Duration(daysUntilExpiry) * 24 * time.Hour)
	return &tls.Certificate{
		Leaf: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: commonName,
			},
			NotAfter: expirationDate,
			Raw:      []byte("test-certificate-data-" + commonName),
			Extensions: []pkix.Extension{
				{Value: []byte("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")},
			},
		},
	}
}

// setupCertificateCheckMW returns a CertificateCheckMW with a configurable CertificateManager.
func setupCertificateCheckMW(t *testing.T, useMutualTLS bool, setupMock func(*mock.MockCertificateManager, *certcheck.MockBackgroundBatcher)) *CertificateCheckMW {
	ctrl := gomock.NewController(t)
	mockCertManager := mock.NewMockCertificateManager(ctrl)
	mockBackgroundBatcher := certcheck.NewMockBackgroundBatcher(ctrl)

	// Generate a unique test prefix to avoid key clashes between test runs
	testPrefix := fmt.Sprintf("test-%d-", time.Now().UnixNano())

	// Create gateway configuration
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

	// Create gateway
	gw := &Gateway{
		CertificateManager: mockCertManager,
	}
	gw.StorageConnectionHandler = storage.NewConnectionHandler(context.Background())
	gw.SetConfig(gwConfig)

	// Connect to Redis
	ctx := context.Background()
	gw.StorageConnectionHandler.Connect(ctx, func() {
		// Connection callback - do nothing for tests
	}, &gwConfig)

	// Wait for connection to be established
	timeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connected := gw.StorageConnectionHandler.WaitConnect(timeout)
	if !connected {
		t.Fatalf("Redis connection was not established in test setup")
	}

	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{
			APIID:              "test-api-id",
			OrgID:              "test-org-id",
			UseMutualTLSAuth:   useMutualTLS,
			ClientCertificates: []string{"cert1"},
		},
		GlobalConfig: gwConfig,
	}

	mw := &CertificateCheckMW{
		BaseMiddleware: &BaseMiddleware{
			Spec: spec,
			Gw:   gw,
		},
	}

	// Initialize Redis store with unique test prefix
	mw.store = &storage.RedisCluster{
		KeyPrefix:         fmt.Sprintf("cert-cooldown:%s", testPrefix),
		ConnectionHandler: gw.StorageConnectionHandler,
	}
	mw.store.Connect()

	mw.expiryCheckBatcher = mockBackgroundBatcher

	if setupMock != nil {
		setupMock(mockCertManager, mockBackgroundBatcher)
	}

	return mw
}

// Table-driven tests for Name method
func TestCertificateCheckMW_Name(t *testing.T) {
	t.Parallel()

	mw := setupCertificateCheckMW(t, true, nil)
	assert.Equal(t, "CertificateCheckMW", mw.Name())
}

// Table-driven tests for EnabledForSpec method
func TestCertificateCheckMW_EnabledForSpec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		useMutualTLS bool
		enabled      bool
	}{
		{"MutualTLS enabled", true, true},
		{"MutualTLS disabled", false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mw := setupCertificateCheckMW(t, tc.useMutualTLS, nil)
			assert.Equal(t, tc.enabled, mw.EnabledForSpec())
		})
	}
}

// Comprehensive table-driven test for ProcessRequest method
func TestCertificateCheckMW_ProcessRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		useMutualTLS   bool
		statusOkIgnore bool
		req            *http.Request
		certs          []*tls.Certificate
		peerCerts      []*x509.Certificate
		expectCode     int
		expectErr      bool
	}{
		// Basic paths
		{
			name:           "StatusOkAndIgnore short-circuits",
			useMutualTLS:   true,
			statusOkIgnore: true,
			req:            &http.Request{},
			expectCode:     http.StatusOK,
			expectErr:      false,
		},
		{
			name:         "No MutualTLS returns OK",
			useMutualTLS: false,
			req:          &http.Request{},
			expectCode:   http.StatusOK,
			expectErr:    false,
		},
		// Edge cases
		{
			name:       "Nil request returns OK",
			req:        nil,
			expectCode: http.StatusOK,
			expectErr:  false,
		},
		{
			name:       "Request without TLS returns OK when no MutualTLS",
			req:        &http.Request{},
			expectCode: http.StatusOK,
			expectErr:  false,
		},
		// MutualTLS specific cases
		{
			name:         "MutualTLS without TLS returns Forbidden",
			useMutualTLS: true,
			req:          &http.Request{}, // No TLS
			expectCode:   http.StatusForbidden,
			expectErr:    true,
		},
		{
			name:         "MutualTLS with empty cert list returns Forbidden",
			useMutualTLS: true,
			req:          &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}},
			certs:        []*tls.Certificate{},
			expectCode:   http.StatusForbidden,
			expectErr:    true,
		},
		{
			name:         "MutualTLS with valid certificate returns OK",
			useMutualTLS: true,
			peerCerts:    []*x509.Certificate{{Raw: []byte("abc"), NotAfter: time.Now().Add(time.Hour), Extensions: []pkix.Extension{{Value: []byte("dummy")}}}},
			certs:        []*tls.Certificate{{Leaf: &x509.Certificate{Extensions: []pkix.Extension{{Value: []byte("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")}}, NotAfter: time.Now().Add(time.Hour)}}},
			req:          &http.Request{},
			expectCode:   http.StatusOK,
			expectErr:    false,
		},
		{
			name:         "MutualTLS with expiring certificate returns OK but fires event",
			useMutualTLS: true,
			peerCerts:    []*x509.Certificate{{Raw: []byte("abc"), NotAfter: time.Now().Add(time.Hour), Extensions: []pkix.Extension{{Value: []byte("dummy")}}}},
			certs:        []*tls.Certificate{{Leaf: &x509.Certificate{Extensions: []pkix.Extension{{Value: []byte("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")}}, NotAfter: time.Now().Add(15 * 24 * time.Hour)}}},
			req:          &http.Request{},
			expectCode:   http.StatusOK,
			expectErr:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Set up request context if needed
			if tc.req != nil && tc.statusOkIgnore {
				ctxSetRequestStatus(tc.req, StatusOkAndIgnore)
			}

			// Set up PeerCertificates if specified
			if tc.peerCerts != nil && tc.req != nil {
				tc.req.TLS = &tls.ConnectionState{PeerCertificates: tc.peerCerts}
			}

			// Use a custom CertificateManager if certs are specified
			var setupMock func(*mock.MockCertificateManager, *certcheck.MockBackgroundBatcher)
			if tc.useMutualTLS {
				setupMock = func(m *mock.MockCertificateManager, bg *certcheck.MockBackgroundBatcher) {
					m.EXPECT().
						List(gomock.Any(), gomock.Any()).
						Return(tc.certs).
						AnyTimes()

					bg.EXPECT().Add(gomock.AssignableToTypeOf(certcheck.CertInfo{})).
						AnyTimes()
				}
			} else {
				setupMock = func(m *mock.MockCertificateManager, bg *certcheck.MockBackgroundBatcher) {
					bg.EXPECT().Add(gomock.AssignableToTypeOf(certcheck.CertInfo{})).
						AnyTimes()
				}
			}
			mw := setupCertificateCheckMW(t, tc.useMutualTLS, setupMock)

			err, code := mw.ProcessRequest(nil, tc.req, nil)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.expectCode, code)
		})
	}
}

func TestCertificateCheckMiddleware_InitAndUnload(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	redisMock := mockstorage.NewMockHandler(ctrl)
	logger, _ := logrustest.NewNullLogger()

	gw := &Gateway{}
	gwConfig := config.Config{
		Security: config.SecurityConfig{
			CertificateExpiryMonitor: config.CertificateExpiryMonitorConfig{},
		},
	}
	gw.SetConfig(gwConfig)

	mw := CertificateCheckMW{
		BaseMiddleware: &BaseMiddleware{
			Gw:     gw,
			logger: logrus.NewEntry(logger),
		},
		store: redisMock, // redis will be tested in integration tests
	}

	mw.Init()
	mw.Unload()

	assert.Eventuallyf(t, func() bool {
		<-mw.expiryCheckContext.Done()
		return true
	}, 10*time.Millisecond, 5*time.Millisecond, "Unload did not stop cert check batcher")
}
