package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	rsaPrivateKey = "RSA PRIVATE KEY"
	certificate   = "CERTIFICATE"
)

var certSubject = pkix.Name{
	Organization:  []string{"Tyk Technologies Ltd"},
	Country:       []string{"UK"},
	Province:      []string{"London"},
	Locality:      []string{"London"},
	StreetAddress: []string{"Worship Street"},
}

// GenerateRootCertAndKey generates a root certificate and private key for testing purposes.
// It returns the root certificate and private key in PEM format along with an error, if any.
//
// Parameters:
// - tb: The testing.TB instance to log errors and fail the test if necessary.
//
// Returns:
// - []byte: The root certificate in PEM format.
// - []byte: The root private key in PEM format.
// - error: Any error encountered during the generation.
func GenerateRootCertAndKey(tb testing.TB) ([]byte, []byte, error) {
	tb.Helper()
	// Generate RSA key pair
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create a template for the root certificate
	rootCertTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               certSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create the root certificate
	rootCertDER, err := x509.CreateCertificate(rand.Reader, &rootCertTemplate, &rootCertTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode the root certificate to PEM format
	var rootCertPEM bytes.Buffer
	assert.NoError(tb, pem.Encode(&rootCertPEM, &pem.Block{Type: certificate, Bytes: rootCertDER}))

	// Encode the root private key to PEM format
	var rootKeyPEM bytes.Buffer
	assert.NoError(tb, pem.Encode(&rootKeyPEM, &pem.Block{Type: rsaPrivateKey, Bytes: x509.MarshalPKCS1PrivateKey(rootKey)}))

	return rootCertPEM.Bytes(), rootKeyPEM.Bytes(), nil
}

// GenerateServerCertAndKeyPEM generates a server certificate and private key signed by the given root certificate
// and key for testing purposes.
// It returns the server certificate and private key in PEM format along with an error, if any.
//
// Parameters:
// - tb: The testing.TB instance to log errors and fail the test if necessary.
// - rootCertPEM: The root certificate in PEM format.
// - rootKeyPEM: The root private key in PEM format.
//
// Returns:
// - *bytes.Buffer: The server certificate in PEM format.
// - *bytes.Buffer: The server private key in PEM format.
// - error: Any error encountered during the generation.
func GenerateServerCertAndKeyPEM(tb testing.TB, rootCertPEM, rootKeyPEM []byte) (*bytes.Buffer, *bytes.Buffer, error) {
	tb.Helper()

	rootCert, rootKey, err := decodeRootCertAndKey(rootCertPEM, rootKeyPEM)
	assert.NoError(tb, err)

	// Generate RSA key pair for the server
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create a template for the server certificate
	serverCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      certSubject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0), // 1 year
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	// Create the server certificate signed by the root CA
	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverCertTemplate, rootCert, &serverKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode the server certificate to PEM format
	var serverCertPEM bytes.Buffer
	assert.NoError(tb, pem.Encode(&serverCertPEM, &pem.Block{Type: certificate, Bytes: serverCertDER}))

	// Encode the server private key to PEM format
	var serverKeyPEM bytes.Buffer
	assert.NoError(tb, pem.Encode(&serverKeyPEM, &pem.Block{Type: rsaPrivateKey, Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}))

	return &serverCertPEM, &serverKeyPEM, nil
}

// GenerateServerCertAndKeyChain generates a server certificate and private key signed by the given root certificate and key,
// and includes the root certificate in the chain for testing purposes.
// It returns the server certificate chain and private key in PEM format along with an error, if any.
//
// Parameters:
// - tb: The testing.TB instance to log errors and fail the test if necessary.
// - rootCertPEM: The root certificate in PEM format.
// - rootKeyPEM: The root private key in PEM format.
//
// Returns:
// - *bytes.Buffer: The server certificate chain in PEM format.
// - *bytes.Buffer: The server private key in PEM format.
// - error: Any error encountered during the generation.
func GenerateServerCertAndKeyChain(tb testing.TB, rootCertPEM, rootKeyPEM []byte) (*bytes.Buffer, *bytes.Buffer, error) {
	tb.Helper()
	serverCertPEM, serverKeyPEM, err := GenerateServerCertAndKeyPEM(tb, rootCertPEM, rootKeyPEM)
	assert.NoError(tb, err)
	// Include the root certificate in the client certificate chain
	_, _ = serverCertPEM.Write(rootCertPEM)

	return serverCertPEM, serverKeyPEM, nil
}

// GenerateClientCertAndKeyPEM generates a client certificate and private key signed by the given root certificate
// and key for testing purposes.
// It returns the client certificate and private key in PEM format along with an error, if any.
//
// Parameters:
// - tb: The testing.TB instance to log errors and fail the test if necessary.
// - rootCertPEM: The root certificate in PEM format.
// - rootKeyPEM: The root private key in PEM format.
//
// Returns:
// - *bytes.Buffer: The client certificate in PEM format.
// - *bytes.Buffer: The client private key in PEM format.
// - error: Any error encountered during the generation.
func GenerateClientCertAndKeyPEM(tb testing.TB, rootCertPEM, rootKeyPEM []byte) (*bytes.Buffer, *bytes.Buffer, error) {
	tb.Helper()

	rootCert, rootKey, err := decodeRootCertAndKey(rootCertPEM, rootKeyPEM)
	assert.NoError(tb, err)

	// Generate RSA key pair for the client
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create a template for the client certificate
	clientCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      certSubject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0), // 1 year
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Create the client certificate signed by the root CA
	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientCertTemplate, rootCert, &clientKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode the client certificate to PEM format
	var clientCertPEM bytes.Buffer
	assert.NoError(tb, pem.Encode(&clientCertPEM, &pem.Block{Type: certificate, Bytes: clientCertDER}))

	// Encode the client private key to PEM format
	var clientKeyPEM bytes.Buffer
	assert.NoError(tb, pem.Encode(&clientKeyPEM, &pem.Block{Type: rsaPrivateKey, Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}))

	return &clientCertPEM, &clientKeyPEM, nil
}

// GenerateClientCertAndKeyChain generates a client certificate and private key signed by the given root certificate and key,
// and includes the root certificate in the chain for testing purposes.
// It returns the client certificate chain and private key in PEM format along with an error, if any.
//
// Parameters:
// - tb: The testing.TB instance to log errors and fail the test if necessary.
// - rootCertPEM: The root certificate in PEM format.
// - rootKeyPEM: The root private key in PEM format.
//
// Returns:
// - *bytes.Buffer: The client certificate chain in PEM format.
// - *bytes.Buffer: The client private key in PEM format.
// - error: Any error encountered during the generation.
func GenerateClientCertAndKeyChain(tb testing.TB, rootCertPEM, rootKeyPEM []byte) (*bytes.Buffer, *bytes.Buffer, error) {
	tb.Helper()
	clientCertPEM, clientKeyPEM, err := GenerateClientCertAndKeyPEM(tb, rootCertPEM, rootKeyPEM)
	assert.NoError(tb, err)
	// Include the root certificate in the client certificate chain
	_, _ = clientCertPEM.Write(rootCertPEM)

	return clientCertPEM, clientKeyPEM, nil
}

func decodeRootCertAndKey(rootCertPEM, rootKeyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Decode the root certificate
	rootCertBlock, _ := pem.Decode(rootCertPEM)
	if rootCertBlock == nil || rootCertBlock.Type != certificate {
		return nil, nil, fmt.Errorf("failed to decode root certificate PEM")
	}

	rootCert, err := x509.ParseCertificate(rootCertBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Decode the root private key
	rootKeyBlock, _ := pem.Decode(rootKeyPEM)
	if rootKeyBlock == nil || rootKeyBlock.Type != rsaPrivateKey {
		return nil, nil, fmt.Errorf("failed to decode root key PEM")
	}
	rootKey, err := x509.ParsePKCS1PrivateKey(rootKeyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return rootCert, rootKey, nil
}
