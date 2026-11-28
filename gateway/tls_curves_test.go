//go:build !fips

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

func newTestGatewayForCurves(t *testing.T) *Gateway {
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

func TestDefaultCurvePreferences(t *testing.T) {
	curves := defaultCurvePreferences()
	assert.Nil(t, curves, "standard (!fips) builds must return nil CurvePreferences to allow Go runtime default curve negotiation")
}

func TestTLSClientConfigCurvePreferences(t *testing.T) {
	spec := &APISpec{
		APIDefinition: &apidef.APIDefinition{},
	}
	gw := newTestGatewayForCurves(t)
	cfg := tlsClientConfig(spec, gw)
	require.NotNil(t, cfg)
	assert.Nil(t, cfg.CurvePreferences, "tlsClientConfig should have nil CurvePreferences in default builds")
}

func TestGetTLSConfigForClientCurvePreferences(t *testing.T) {
	gw := newTestGatewayForCurves(t)

	baseConfig := &tls.Config{}
	fn := gw.getTLSConfigForClient(baseConfig, 8080)
	require.NotNil(t, fn)

	clientConfig, err := fn(&tls.ClientHelloInfo{ServerName: "localhost"})
	require.NoError(t, err)
	require.NotNil(t, clientConfig)
	assert.Nil(t, clientConfig.CurvePreferences, "clientConfig should have nil CurvePreferences in default builds")
}

func TestGetTLSConfigForClientPreservesExistingCurvePreferences(t *testing.T) {
	gw := newTestGatewayForCurves(t)

	customCurves := []tls.CurveID{tls.CurveP256}
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

func TestReverseProxyHTTPTransportCurvePreferences(t *testing.T) {
	gw := newTestGatewayForCurves(t)
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
	assert.Nil(t, rt.transport.TLSClientConfig.CurvePreferences)
}

func TestTLSHandshake_DefaultAllowsX25519AndPostQuantum(t *testing.T) {
	cert := testSelfSignedECDSACert(t)

	tests := []struct {
		name          string
		clientCurves  []tls.CurveID
		expectedCurve tls.CurveID
	}{
		{
			name:          "negotiates X25519MLKEM768",
			clientCurves:  []tls.CurveID{tls.X25519MLKEM768},
			expectedCurve: tls.X25519MLKEM768,
		},
		{
			name:          "negotiates X25519",
			clientCurves:  []tls.CurveID{tls.X25519},
			expectedCurve: tls.X25519,
		},
		{
			name:          "negotiates CurveP256",
			clientCurves:  []tls.CurveID{tls.CurveP256},
			expectedCurve: tls.CurveP256,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			serverConfig := &tls.Config{
				Certificates:     []tls.Certificate{cert},
				CurvePreferences: defaultCurvePreferences(),
			}

			clientConfig := &tls.Config{
				InsecureSkipVerify: true,
				CurvePreferences:   tc.clientCurves,
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
			assert.Equal(t, tc.expectedCurve, clientTLS.ConnectionState().CurveID)
		})
	}
}
