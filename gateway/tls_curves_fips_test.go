//go:build fips

package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs/mock"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/dnscache"
)

func newTestGatewayForCurvesFIPS(t *testing.T) *Gateway {
	tlsConfigCache.Flush()
	t.Cleanup(tlsConfigCache.Flush)

	ctrl := gomock.NewController(t)
	mockCertManager := mock.NewMockCertificateManager(ctrl)
	mockCertManager.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	gw := &Gateway{
		CertificateManager: mockCertManager,
		dnsCacheManager:    dnscache.NewDnsCacheManager(""),
	}
	gw.SetConfig(config.Config{})
	return gw
}

func testSelfSignedECDSACert(t *testing.T) tls.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

func TestDefaultCurvePreferences_FIPS(t *testing.T) {
	curves := defaultCurvePreferences()
	require.NotNil(t, curves, "FIPS builds must return explicit CurvePreferences")

	expectedCurves := []tls.CurveID{
		tls.SecP256r1MLKEM768,
		tls.SecP384r1MLKEM1024,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	}
	assert.Equal(t, expectedCurves, curves, "FIPS CurvePreferences must match NIST-approved curves and post-quantum hybrids in expected order")

	// Ensure unapproved curves (X25519 and X25519MLKEM768) are not included
	for _, c := range curves {
		assert.NotEqual(t, tls.X25519, c, "X25519 must not be in FIPS CurvePreferences")
		assert.NotEqual(t, tls.X25519MLKEM768, c, "X25519MLKEM768 must not be in FIPS CurvePreferences")
	}
}

func TestTLSClientConfigCurvePreferences_FIPS(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{},
	}
	gw := newTestGatewayForCurvesFIPS(t)
	cfg := tlsClientConfig(spec, gw)
	require.NotNil(t, cfg)

	expectedCurves := []tls.CurveID{
		tls.SecP256r1MLKEM768,
		tls.SecP384r1MLKEM1024,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	}
	assert.Equal(t, expectedCurves, cfg.CurvePreferences)
}

func TestGetTLSConfigForClientCurvePreferences_FIPS(t *testing.T) {
	gw := newTestGatewayForCurvesFIPS(t)

	baseConfig := &tls.Config{}
	fn := gw.getTLSConfigForClient(baseConfig, 8080)
	require.NotNil(t, fn)

	clientConfig, err := fn(&tls.ClientHelloInfo{ServerName: "localhost"})
	require.NoError(t, err)
	require.NotNil(t, clientConfig)

	expectedCurves := []tls.CurveID{
		tls.SecP256r1MLKEM768,
		tls.SecP384r1MLKEM1024,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	}
	assert.Equal(t, expectedCurves, clientConfig.CurvePreferences)
}

func TestGetTLSConfigForClientPreservesExistingCurvePreferences_FIPS(t *testing.T) {
	gw := newTestGatewayForCurvesFIPS(t)

	customCurves := []tls.CurveID{tls.CurveP384}
	baseConfig := &tls.Config{
		CurvePreferences: customCurves,
	}
	fn := gw.getTLSConfigForClient(baseConfig, 8080)
	require.NotNil(t, fn)

	clientConfig, err := fn(&tls.ClientHelloInfo{ServerName: "localhost"})
	require.NoError(t, err)
	require.NotNil(t, clientConfig)
	assert.Equal(t, customCurves, clientConfig.CurvePreferences)
}

func TestReverseProxyHTTPTransportCurvePreferences_FIPS(t *testing.T) {
	gw := newTestGatewayForCurvesFIPS(t)
	logger, _ := logrustest.NewNullLogger()

	proxy := &ReverseProxy{
		TykAPISpec: &APISpec{
			APIDefinition: &apidef.APIDefinition{},
		},
		Gw:     gw,
		logger: logrus.NewEntry(logger),
	}

	req, err := http.NewRequest("GET", "https://upstream.example.com/test", nil)
	require.NoError(t, err)

	rt := proxy.httpTransport(10, req, req)
	require.NotNil(t, rt)
	require.NotNil(t, rt.transport)
	require.NotNil(t, rt.transport.TLSClientConfig)

	expectedCurves := []tls.CurveID{
		tls.SecP256r1MLKEM768,
		tls.SecP384r1MLKEM1024,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	}
	assert.Equal(t, expectedCurves, rt.transport.TLSClientConfig.CurvePreferences)
}

func TestTLSHandshake_FIPSNISTAndHybrids(t *testing.T) {
	cert := testSelfSignedECDSACert(t)

	t.Run("negotiates SecP256r1MLKEM768 hybrid", func(t *testing.T) {
		serverConfig := &tls.Config{
			Certificates:     []tls.Certificate{cert},
			CurvePreferences: defaultCurvePreferences(),
		}

		clientConfig := &tls.Config{
			InsecureSkipVerify: true,
			CurvePreferences:   []tls.CurveID{tls.SecP256r1MLKEM768},
		}

		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()

		serverTLS := tls.Server(serverConn, serverConfig)
		clientTLS := tls.Client(clientConn, clientConfig)

		serverErrChan := make(chan error, 1)
		go func() {
			serverErrChan <- serverTLS.Handshake()
		}()

		clientErr := clientTLS.Handshake()
		serverErr := <-serverErrChan

		require.NoError(t, clientErr)
		require.NoError(t, serverErr)
		assert.Equal(t, tls.SecP256r1MLKEM768, clientTLS.ConnectionState().CurveID)
	})

	t.Run("negotiates CurveP256 classical", func(t *testing.T) {
		serverConfig := &tls.Config{
			Certificates:     []tls.Certificate{cert},
			CurvePreferences: defaultCurvePreferences(),
		}

		clientConfig := &tls.Config{
			InsecureSkipVerify: true,
			CurvePreferences:   []tls.CurveID{tls.CurveP256},
		}

		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()

		serverTLS := tls.Server(serverConn, serverConfig)
		clientTLS := tls.Client(clientConn, clientConfig)

		serverErrChan := make(chan error, 1)
		go func() {
			serverErrChan <- serverTLS.Handshake()
		}()

		clientErr := clientTLS.Handshake()
		serverErr := <-serverErrChan

		require.NoError(t, clientErr)
		require.NoError(t, serverErr)
		assert.Equal(t, tls.CurveP256, clientTLS.ConnectionState().CurveID)
	})

	t.Run("rejects client offering only unapproved X25519", func(t *testing.T) {
		serverConfig := &tls.Config{
			Certificates:     []tls.Certificate{cert},
			CurvePreferences: defaultCurvePreferences(),
		}

		clientConfig := &tls.Config{
			InsecureSkipVerify: true,
			CurvePreferences:   []tls.CurveID{tls.X25519},
		}

		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()

		serverTLS := tls.Server(serverConn, serverConfig)
		clientTLS := tls.Client(clientConn, clientConfig)

		serverErrChan := make(chan error, 1)
		go func() {
			serverErrChan <- serverTLS.Handshake()
		}()

		clientErr := clientTLS.Handshake()
		serverErr := <-serverErrChan

		assert.Error(t, clientErr, "client handshake offering only X25519 should fail against FIPS server")
		assert.Error(t, serverErr, "server handshake should fail when no curves overlap")
	})

	t.Run("rejects client offering only unapproved X25519MLKEM768", func(t *testing.T) {
		serverConfig := &tls.Config{
			Certificates:     []tls.Certificate{cert},
			CurvePreferences: defaultCurvePreferences(),
		}

		clientConfig := &tls.Config{
			InsecureSkipVerify: true,
			CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
		}

		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()

		serverTLS := tls.Server(serverConn, serverConfig)
		clientTLS := tls.Client(clientConn, clientConfig)

		serverErrChan := make(chan error, 1)
		go func() {
			serverErrChan <- serverTLS.Handshake()
		}()

		clientErr := clientTLS.Handshake()
		serverErr := <-serverErrChan

		assert.Error(t, clientErr, "client handshake offering only X25519MLKEM768 should fail against FIPS server")
		assert.Error(t, serverErr, "server handshake should fail when no curves overlap")
	})
}
