package crypto

import (
	"crypto/tls"
	"testing"
)

func TestNewCipher(t *testing.T) {
	mockCipher := &tls.CipherSuite{
		ID:                uint16(0x0001),
		Name:              "TLS_MOCK_CIPHER",
		Insecure:          false,
		SupportedVersions: []uint16{tls.VersionTLS12, tls.VersionTLS13},
	}

	cipher := NewCipher(mockCipher)

	if cipher.ID != mockCipher.ID {
		t.Errorf("Expected ID %d, got %d", mockCipher.ID, cipher.ID)
	}
	if cipher.Name != mockCipher.Name {
		t.Errorf("Expected Name %s, got %s", mockCipher.Name, cipher.Name)
	}
	if cipher.Insecure != mockCipher.Insecure {
		t.Errorf("Expected Insecure %t, got %t", mockCipher.Insecure, cipher.Insecure)
	}
	if len(cipher.TLS) != 2 || cipher.TLS[0] != "1.2" || cipher.TLS[1] != "1.3" {
		t.Errorf("Expected TLS versions [1.2, 1.3], got %v", cipher.TLS)
	}
}

func TestGetCiphers(t *testing.T) {
	ciphers := GetCiphers()
	if len(ciphers) == 0 {
		t.Error("Expected non-empty cipher list")
	}

	for _, cipher := range ciphers {
		if cipher.ID == 0 || cipher.Name == "" {
			t.Errorf("Invalid cipher: %v", cipher)
		}
	}
}

var legacyCipherSuites = []string{
	"TLS_RSA_WITH_AES_128_CBC_SHA",
	"TLS_RSA_WITH_RC4_128_SHA",
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	"TLS_RSA_WITH_AES_256_CBC_SHA",
	"TLS_RSA_WITH_AES_128_CBC_SHA256",
	"TLS_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}

func TestLegacyCipherSuites(t *testing.T) {
	ciphers := GetCiphers()

	totalCiphers := map[string]bool{}

	for _, cipher := range ciphers {
		totalCiphers[cipher.Name] = true
	}

	for _, cipher := range legacyCipherSuites {
		if !totalCiphers[cipher] {
			t.Errorf("Expected %s to be removed", cipher)
		}
	}
}

func TestResolveCipher(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected uint16
		hasError bool
	}{
		{"Valid cipher", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xc02f, false},
		{"Invalid cipher", "INVALID_CIPHER", 0, true},
		{"Case insensitive", "tls_ecdhe_rsa_with_aes_128_gcm_sha256", 0xc02f, false},
		{"Empty input", "", 0, true},
		{"Partial match", "TLS_ECDHE", 0, true},
		{"Legacy cipher TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", 0xcca8, false},
		{"Legacy cipher TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", 0xcca9, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ResolveCipher(tc.input)
			if tc.hasError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.hasError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("Expected %d, got %d", tc.expected, result)
			}
		})
	}
}

func TestTLSVersions(t *testing.T) {
	testCases := []struct {
		name     string
		input    []uint16
		expected []string
	}{
		{"All versions", []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}, []string{"1.0", "1.1", "1.2", "1.3"}},
		{"Unknown version", []uint16{0x0000}, []string{""}},
		{"Mixed versions", []uint16{tls.VersionTLS12, 0x0000, tls.VersionTLS13}, []string{"1.2", "", "1.3"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := TLSVersions(tc.input)
			if len(result) != len(tc.expected) {
				t.Errorf("Expected %d versions, got %d", len(tc.expected), len(result))
			}
			for i, v := range result {
				if v != tc.expected[i] {
					t.Errorf("Expected version %s at index %d, got %s", tc.expected[i], i, v)
				}
			}
		})
	}
}

func TestCipherNamesEqual(t *testing.T) {
	cases := map[string]struct {
		s1, s2   string
		expected bool
	}{
		"canonical match": {
			s1:       "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			s2:       "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			expected: true,
		},
		"legacy to canonical": {
			s1:       "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
			s2:       "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			expected: true,
		},
		"canonical to legacy": {
			s1:       "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			s2:       "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
			expected: false,
		},
		"ecdsa legacy to canonical": {
			s1:       "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
			s2:       "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
			expected: true,
		},
		"ecdsa canonical to legacy": {
			s1:       "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
			s2:       "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
			expected: false,
		},
		"case-insensitive": {
			s1:       "tls_ecdhe_rsa_with_chacha20_poly1305",
			s2:       "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			expected: true,
		},
		"no match": {
			s1:       "TLS_FAKE_CIPHER",
			s2:       "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			expected: false,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := cipherNamesEqual(tc.s1, tc.s2); got != tc.expected {
				t.Errorf("compareCipherName(%q, %q) = %v; want %v", tc.s1, tc.s2, got, tc.expected)
			}
		})
	}
}
