package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	ErrCertExpired = errors.New("Certificate has expired")
)

// HexSHA256 calculates the SHA256 hash of the provided certificate bytes
// and returns the result as a hexadecimal string.
func HexSHA256(cert []byte) string {
	certSHA := sha256.Sum256(cert)
	return hex.EncodeToString(certSHA[:])
}

// GenCertificate generates a self-signed X.509 certificate based on the provided template.
// It returns the certificate, private key, combined PEM bytes, and a tls.Certificate.
//
// The function generates a private key, sets the certificate fields if not already set,
// and creates the certificate in PEM format. Use NotBefore and NotAfter in template to control
// the certificate expiry.
// If the NotBefore field of the template is zero-valued, it is set to the current time.
// If the NotAfter field is zero-valued, it is set to one hour after the NotBefore time.
// The generated certificate is then encoded to PEM format along with the private key.
//
// A tls.Certificate is created using the PEM-encoded certificate and private key.
// If setLeaf is true, the certificate's Leaf field is set to the template.
func GenCertificate(template *x509.Certificate, setLeaf bool) ([]byte, []byte, []byte, tls.Certificate) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template.SerialNumber = serialNumber
	template.BasicConstraintsValid = true
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now()
	}

	if template.NotAfter.IsZero() {
		template.NotAfter = template.NotBefore.Add(time.Hour)
	}

	derBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)

	var certPem, keyPem bytes.Buffer
	pem.Encode(&certPem, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(&keyPem, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	clientCert, _ := tls.X509KeyPair(certPem.Bytes(), keyPem.Bytes())
	if setLeaf {
		clientCert.Leaf = template
	}
	combinedPEM := bytes.Join([][]byte{certPem.Bytes(), keyPem.Bytes()}, []byte("\n"))

	return certPem.Bytes(), keyPem.Bytes(), combinedPEM, clientCert
}

// GenServerCertificate generates a self-signed server certificate for "localhost"
// with DNS names "localhost" and IP addresses 127.0.0.1 and ::.
// It returns the certificate, private key, combined PEM bytes, and a tls.Certificate.
func GenServerCertificate() ([]byte, []byte, []byte, tls.Certificate) {
	certPem, privPem, combinedPEM, cert := GenCertificate(&x509.Certificate{
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::")},
	}, false)

	return certPem, privPem, combinedPEM, cert
}

// ValidateRequestCerts validates client TLS certificates against a list of allowed certificates configured in API definition.
// It returns an error if TLS is not enabled, the client certificate is missing, or if it is not allowed or expired.
func ValidateRequestCerts(r *http.Request, certs []*tls.Certificate) error {
	if r.TLS == nil {
		return errors.New("TLS not enabled")
	}

	if len(r.TLS.PeerCertificates) == 0 {
		return errors.New("Client TLS certificate is required")
	}

	for _, peerCertificate := range r.TLS.PeerCertificates {
		certID := HexSHA256(peerCertificate.Raw)
		for _, cert := range certs {
			// In case a cert can't be parsed or is invalid,
			// it will be present in the cert list as 'nil'
			if cert == nil {
				// Invalid cert, continue to next one
				continue
			}

			// Extensions[0] contains cache of certificate SHA256
			if string(cert.Leaf.Extensions[0].Value) == certID {
				if time.Now().After(cert.Leaf.NotAfter) {
					return ErrCertExpired
				}
				// Happy flow, we matched a certificate
				return nil
			}
		}
	}

	return errors.New("Certificate with SHA256 " + HexSHA256(r.TLS.PeerCertificates[0].Raw) + " not allowed")
}

// IsPublicKey verifies if given certificate is a public key only.
func IsPublicKey(cert *tls.Certificate) bool {
	return cert.Leaf != nil && strings.HasPrefix(cert.Leaf.Subject.CommonName, "Public Key: ")
}

// PrefixPublicKeyCommonName returns x509.Certificate with prefixed CommonName.
// This is used in UI/response to hint the type certificate during listing.
func PrefixPublicKeyCommonName(blockBytes []byte) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Public Key: " + HexSHA256(blockBytes),
		},
	}
}

// GenerateRSAPublicKey generates an RSA public key.
func GenerateRSAPublicKey(tb testing.TB) []byte {
	tb.Helper()
	// Generate a private key.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(tb, err)

	// Derive the public key from the private key.
	publicKey := &priv.PublicKey

	// Save the public key in PEM format.
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	assert.NoError(tb, err)

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	publicKeyPEM := pem.EncodeToMemory(publicKeyBlock)
	return publicKeyPEM
}
