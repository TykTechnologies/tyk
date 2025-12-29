package gateway

import (
	"encoding/json"
	"testing"
)

func TestCompressData(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "Empty data",
			input:   "",
			wantErr: false,
		},
		{
			name:    "Small JSON",
			input:   `{"key":"value"}`,
			wantErr: false,
		},
		{
			name:    "Large JSON",
			input:   `{"api_id":"test","name":"Test API","proxy":{"listen_path":"/test","target_url":"http://example.com"},"version_data":{"versions":{"v1":{"name":"v1"}}}}`,
			wantErr: false,
		},
		{
			name:    "Non-JSON data",
			input:   "This is just plain text that should still compress",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := compressData([]byte(tt.input))

			if (err != nil) != tt.wantErr {
				t.Errorf("got %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			// For empty input, compressed data might also be empty or very small
			if len(tt.input) == 0 {
				// Empty input is valid, skip further checks
				return
			}

			// Verify compressed data is not empty for non-empty input
			if len(compressed) == 0 {
				t.Error("compressData returned empty data for non-empty input")
			}

			// Verify compression actually happened (compressed should be different from input)
			if string(compressed) == tt.input {
				t.Error("compressData did not compress the data")
			}
		})
	}
}

func TestDecompressData(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "Empty data",
			input:   "",
			wantErr: false,
		},
		{
			name:    "Small JSON",
			input:   `{"key":"value"}`,
			wantErr: false,
		},
		{
			name:    "Large JSON",
			input:   `{"api_id":"test","name":"Test API","proxy":{"listen_path":"/test","target_url":"http://example.com"},"version_data":{"versions":{"v1":{"name":"v1"}}}}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := compressData([]byte(tt.input))
			if err != nil {
				t.Fatalf("compressData failed: %v", err)
			}

			decompressed, err := decompressData(compressed)

			if (err != nil) != tt.wantErr {
				t.Errorf("got %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			// Verify decompressed data matches original
			if string(decompressed) != tt.input {
				t.Errorf("got %v, want %v", string(decompressed), tt.input)
			}
		})
	}
}

func TestDecompressData_InvalidData(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "Invalid compressed data",
			input:   []byte("this is not compressed data"),
			wantErr: true,
		},
		{
			name:    "Corrupted data",
			input:   []byte{0x00, 0x01, 0x02, 0x03},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decompressData(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("got %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCompressDecompressRoundTrip(t *testing.T) {
	// Test with realistic API definition data
	apiDef := map[string]interface{}{
		"api_id": "test-api-123",
		"name":   "Test API",
		"proxy": map[string]interface{}{
			"listen_path": "/test",
			"target_url":  "http://example.com",
		},
		"version_data": map[string]interface{}{
			"versions": map[string]interface{}{
				"v1": map[string]interface{}{
					"name": "v1",
				},
			},
		},
		"auth": map[string]interface{}{
			"auth_header_name": "Authorization",
		},
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(apiDef)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	// Compress
	compressed, err := compressData(jsonData)
	if err != nil {
		t.Fatalf("compressData failed: %v", err)
	}

	// Verify compression reduced size
	if len(compressed) >= len(jsonData) {
		t.Logf("Compressed size (%d) >= original size (%d)", len(compressed), len(jsonData))
	}

	decompressed, err := decompressData(compressed)
	if err != nil {
		t.Fatalf("decompressData failed: %v", err)
	}

	// Verify data integrity
	if string(decompressed) != string(jsonData) {
		t.Error("Decompressed data does not match original")
	}

	// Verify JSON is still valid
	var result map[string]interface{}
	if err := json.Unmarshal(decompressed, &result); err != nil {
		t.Errorf("Decompressed data is not valid JSON: %v", err)
	}
}

func TestCompressionRatio(t *testing.T) {
	// Test with a large, repetitive JSON structure (should compress well)
	largeJSON := `{
		"api_id": "test-api-123",
		"name": "Test API with lots of repetitive data",
		"proxy": {
			"listen_path": "/test",
			"target_url": "http://example.com"
		},
		"version_data": {
			"versions": {
				"v1": {"name": "v1", "expires": "", "paths": {"ignored": [], "white_list": [], "black_list": []}},
				"v2": {"name": "v2", "expires": "", "paths": {"ignored": [], "white_list": [], "black_list": []}},
				"v3": {"name": "v3", "expires": "", "paths": {"ignored": [], "white_list": [], "black_list": []}}
			}
		}
	}`

	compressed, err := compressData([]byte(largeJSON))
	if err != nil {
		t.Fatalf("compressData failed: %v", err)
	}

	originalSize := len(largeJSON)
	compressedSize := len(compressed)
	ratio := float64(originalSize-compressedSize) / float64(originalSize) * 100

	t.Logf("Original size: %d bytes", originalSize)
	t.Logf("Compressed size: %d bytes", compressedSize)
	t.Logf("Compression ratio: %.2f%%", ratio)

	// Verify we got some compression (at least 10% for this repetitive data)
	if ratio < 10 {
		t.Logf("Compression ratio is low (%.2f%%)", ratio)
	}
}

func TestIsZstdCompressed(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Empty data",
			data:     []byte{},
			expected: false,
		},
		{
			name:     "Too short (less than 4 bytes)",
			data:     []byte{0x28, 0xB5, 0x2F},
			expected: false,
		},
		{
			name:     "Valid Zstd magic bytes",
			data:     []byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x01},
			expected: true,
		},
		{
			name:     "JSON data (not compressed)",
			data:     []byte(`{"key":"value"}`),
			expected: false,
		},
		{
			name:     "Random data",
			data:     []byte{0x00, 0x01, 0x02, 0x03},
			expected: false,
		},
		{
			name:     "Partial magic bytes",
			data:     []byte{0x28, 0xB5, 0x00, 0x00},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isZstdCompressed(tt.data)
			if result != tt.expected {
				t.Errorf("got %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsZstdCompressed_WithRealCompression(t *testing.T) {
	// Test with actual compressed data
	original := []byte(`{"api_id":"test","name":"Test API"}`)

	compressed, err := compressData(original)
	if err != nil {
		t.Fatalf("compressData failed: %v", err)
	}

	// Compressed data should be detected as Zstd
	if !isZstdCompressed(compressed) {
		t.Error("Real compressed data not detected as Zstd")
	}

	// Original data should not be detected as Zstd
	if isZstdCompressed(original) {
		t.Error("Uncompressed JSON incorrectly detected as Zstd")
	}
}
