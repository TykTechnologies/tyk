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
