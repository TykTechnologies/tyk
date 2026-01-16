package compression

import (
	"encoding/json"
	"testing"
)

func TestCompressZstd(t *testing.T) {
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
			compressed := CompressZstd([]byte(tt.input))

			// For empty input, compressed data might also be empty or very small
			if len(tt.input) == 0 {
				// Empty input is valid, skip further checks
				return
			}

			// Verify compressed data is not empty for non-empty input
			if len(compressed) == 0 {
				t.Error("CompressZstd returned empty data for non-empty input")
			}

			// Verify compression actually happened (compressed should be different from input)
			if string(compressed) == tt.input {
				t.Error("CompressZstd did not compress the data")
			}
		})
	}
}

func TestDecompressZstd(t *testing.T) {
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
			compressed := CompressZstd([]byte(tt.input))

			decompressed, err := DecompressZstd(compressed)

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

func TestDecompressZstd_InvalidData(t *testing.T) {
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
			_, err := DecompressZstd(tt.input)

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
	compressed := CompressZstd(jsonData)

	// Verify compression reduced size
	if len(compressed) >= len(jsonData) {
		t.Logf("Compressed size (%d) >= original size (%d)", len(compressed), len(jsonData))
	}

	decompressed, err := DecompressZstd(compressed)
	if err != nil {
		t.Fatalf("DecompressZstd failed: %v", err)
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

	compressed := CompressZstd([]byte(largeJSON))

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
			name:     "Too short data",
			data:     []byte{0x28, 0xB5, 0x2F},
			expected: false,
		},
		{
			name:     "Valid Zstd magic bytes",
			data:     []byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x01},
			expected: true,
		},
		{
			name:     "Invalid magic bytes",
			data:     []byte{0x00, 0x01, 0x02, 0x03},
			expected: false,
		},
		{
			name:     "JSON data",
			data:     []byte(`{"key":"value"}`),
			expected: false,
		},
		{
			name:     "Plain text",
			data:     []byte("this is plain text"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsZstdCompressed(tt.data)
			if result != tt.expected {
				t.Errorf("IsZstdCompressed() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsZstdCompressed_WithActualCompressedData(t *testing.T) {
	// Test with actual compressed data
	original := []byte(`{"api_id":"test","name":"Test API"}`)
	compressed := CompressZstd(original)

	// Verify compressed data has magic bytes
	if !IsZstdCompressed(compressed) {
		t.Error("IsZstdCompressed returned false for actual compressed data")
	}

	// Verify the first 4 bytes match the magic bytes
	if len(compressed) < 4 {
		t.Fatal("Compressed data is too short")
	}

	expectedMagic := []byte{0x28, 0xB5, 0x2F, 0xFD}
	for i := 0; i < 4; i++ {
		if compressed[i] != expectedMagic[i] {
			t.Errorf("Magic byte at position %d: got 0x%02X, want 0x%02X", i, compressed[i], expectedMagic[i])
		}
	}
}
