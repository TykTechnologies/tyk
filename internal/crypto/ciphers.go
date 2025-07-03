package crypto

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// CipherSuite stores information about a cipher suite.
// It shadows tls.CipherSuite but translates TLS versions to strings.
type CipherSuite struct {
	ID       uint16   `json:"id"`
	Name     string   `json:"name"`
	Insecure bool     `json:"insecure"`
	TLS      []string `json:"tls"`
}

// NewCipher translates tls.CipherSuite to our local type.
func NewCipher(in *tls.CipherSuite) *CipherSuite {
	return &CipherSuite{
		ID:       in.ID,
		Name:     in.Name,
		Insecure: in.Insecure,
		TLS:      TLSVersions(in.SupportedVersions),
	}
}

// String returns a human-readable string for the cipher.
func (c *CipherSuite) String() string {
	return fmt.Sprintf("Cipher ID: %d, Name: %s, Insecure: %t, TLS: %v", c.ID, c.Name, c.Insecure, c.TLS)
}

// TLSVersions will return a list of TLS versions as a string.
func TLSVersions(in []uint16) []string {
	versions := make([]string, len(in))
	for i, v := range in {
		switch v {
		case tls.VersionTLS10:
			versions[i] = "1.0"
		case tls.VersionTLS11:
			versions[i] = "1.1"
		case tls.VersionTLS12:
			versions[i] = "1.2"
		case tls.VersionTLS13:
			versions[i] = "1.3"
		default:
			versions[i] = ""
		}
	}
	return versions
}

// GetCiphers generates a list of CipherSuite from the available ciphers.
func GetCiphers() []*CipherSuite {
	ciphers := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)

	result := make([]*CipherSuite, 0, len(ciphers))

	for _, cipher := range ciphers {
		result = append(result, NewCipher(cipher))
	}

	return result
}

// ResolveCipher translates a string representation of a cipher to its uint16 ID.
// It's case-insensitive when matching the cipher by name.
func ResolveCipher(cipherName string) (uint16, error) {
	ciphers := GetCiphers()
	for _, cipher := range ciphers {
		if cipherNamesEqual(cipherName, cipher.Name) {
			return cipher.ID, nil
		}
	}
	return 0, fmt.Errorf("cipher %s not found", cipherName)
}

func cipherNamesEqual(s1, s2 string) bool {
	// Legacy names for the corresponding cipher suites with the correct _SHA256
	// suffix, retained for backward compatibility.
	// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305   = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
	//
	// Reference:
	// - https://github.com/golang/go/blob/master/src/crypto/tls/cipher_suites.go#L720
	legacyAlias := map[string]string{
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	}

	original := s1

	if alias, ok := legacyAlias[strings.ToUpper(s1)]; ok {
		original = alias
	}

	return strings.EqualFold(original, s2)
}
