package goverify

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
)

type RSAPublicKey struct {
	*rsa.PublicKey
}

// Unsign verifies the message using a rsa-sha256 signature
func (r *RSAPublicKey) Verify(message []byte, sig []byte) error {
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, d, sig)
}
