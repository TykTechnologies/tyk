package certs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"strings"

	tykcrypto "github.com/TykTechnologies/tyk/internal/crypto"
)

// CertificateFingerprint returns the fingerprint the certificate store gives PEM content: the SHA-256
// of its first certificate, or of its first public key when it holds no certificate. A certificate
// store ID is the org ID followed by this fingerprint. Content whose line breaks were collapsed into
// spaces is repaired first, as List does. It returns "" when data holds neither.
func CertificateFingerprint(data []byte) string {
	fingerprint := certificateFingerprint(data)
	if fingerprint == "" {
		if repaired, ok := normalizeCollapsedPEM(data); ok {
			fingerprint = certificateFingerprint(repaired)
		}
	}
	return fingerprint
}

func certificateFingerprint(data []byte) string {
	publicKey := ""
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return publicKey
		}
		switch block.Type {
		case "CERTIFICATE":
			return tykcrypto.HexSHA256(block.Bytes)
		case "PUBLIC KEY":
			if publicKey == "" {
				publicKey = tykcrypto.HexSHA256(block.Bytes)
			}
		}
	}
}

// PublicKeyFingerprint returns the fingerprint ListPublicKeys gives a pinned public key: the SHA-256
// of its first PEM block. It returns "" when data can't be decoded.
func PublicKeyFingerprint(data []byte) string {
	block := decodePublicKeyBlock(data)
	if block == nil {
		return ""
	}
	return tykcrypto.HexSHA256(block.Bytes)
}

// IsStoreID reports whether value has the shape of a certificate store ID: an org ID followed by
// a hex SHA-256 fingerprint. It doesn't check that the certificate is in the store.
func IsStoreID(value string) bool {
	const fingerprintLen = sha256.Size * 2
	if len(value) < fingerprintLen || strings.ContainsAny(value, "/\\") {
		return false
	}
	_, err := hex.DecodeString(value[len(value)-fingerprintLen:])
	return err == nil
}
