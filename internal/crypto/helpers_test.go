package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsPublicKey(t *testing.T) {
	tests := []struct {
		name string
		cert *tls.Certificate
		want bool
	}{
		{
			name: "nil leaf",
			cert: &tls.Certificate{Leaf: nil},
			want: false,
		},
		{
			name: "non public key",
			cert: &tls.Certificate{Leaf: &x509.Certificate{Subject: pkix.Name{CommonName: "Non-Public Key: "}}},
			want: false,
		},
		{
			name: "public key",
			cert: &tls.Certificate{Leaf: WrapPublicKeyInDummyX509Cert([]byte("dummy-value"))},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPublicKey(tt.cert); got != tt.want {
				t.Errorf("IsPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateRSAPublicKey(t *testing.T) {
	pubKey := GenerateRSAPublicKey(t)
	assert.Contains(t, string(pubKey), "PUBLIC KEY")
}
