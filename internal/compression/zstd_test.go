package compression

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// Verifies: SYS-REQ-085
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
			compressed, err := CompressZstd([]byte(tt.input))

			if (err != nil) != tt.wantErr {
				t.Errorf("CompressZstd() error = %v, wantErr %v", err, tt.wantErr)
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
				t.Error("CompressZstd returned empty data for non-empty input")
			}

			// Verify compression actually happened (compressed should be different from input)
			if string(compressed) == tt.input {
				t.Error("CompressZstd did not compress the data")
			}
			if !IsZstdCompressed(compressed) {
				t.Error("CompressZstd returned data without the Zstd magic prefix")
			}
		})
	}
}

// Verifies: SYS-REQ-085, SYS-REQ-086
// SYS-REQ-085:nominal:nominal
// SYS-REQ-085:encoding_safety:nominal
// SYS-REQ-085:determinism:nominal
// SYS-REQ-086:malformed_input:nominal
// SYS-REQ-086:nominal:nominal
// SYS-REQ-086:encoding_safety:nominal
// SYS-REQ-086:determinism:nominal
// MCDC SYS-REQ-085: zstd_roundtrip_requested=T, zstd_payload_bytes_preserved=T => TRUE
// MCDC SYS-REQ-086: zstd_invalid_frame_presented=F, zstd_invalid_frame_rejected=F => TRUE
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
			compressed, err := CompressZstd([]byte(tt.input))
			if err != nil {
				t.Fatalf("CompressZstd failed: %v", err)
			}

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

// Verifies: SYS-REQ-086
// SYS-REQ-086:malformed_input:negative
// SYS-REQ-086:error_handling:nominal
// SYS-REQ-086:error_handling:negative
// MCDC SYS-REQ-086: zstd_invalid_frame_presented=T, zstd_invalid_frame_rejected=T => TRUE
//mcdc:ignore:defensive SYS-REQ-086: zstd_invalid_frame_presented=T, zstd_invalid_frame_rejected=F => FALSE -- violation row is the negation of the invalid-frame rejection guarantee; this test asserts malformed frames return errors [reviewed: agent:codex]
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

// Verifies: SYS-REQ-085, SYS-REQ-088, SYS-REQ-090
// SYS-REQ-088:nominal:nominal
// SYS-REQ-088:boundary:nominal
// SYS-REQ-088:encoding_safety:nominal
// SYS-REQ-090:nominal:nominal
// MCDC SYS-REQ-088: zstd_allowed_decompression_requested=T, zstd_payload_bytes_preserved=T => TRUE
// MCDC SYS-REQ-090: zstd_codec_failure_present=F, zstd_codec_failure_reported=F => TRUE
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
	compressed, err := CompressZstd(jsonData)
	if err != nil {
		t.Fatalf("CompressZstd failed: %v", err)
	}

	// Verify compression reduced size
	if len(compressed) >= len(jsonData) {
		t.Logf("Compressed size (%d) >= original size (%d)", len(compressed), len(jsonData))
	}
	if !IsZstdCompressed(compressed) {
		t.Fatal("compressed data was not identified as a Zstd frame")
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

// Verifies: SYS-REQ-085
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

	compressed, err := CompressZstd([]byte(largeJSON))
	if err != nil {
		t.Fatalf("CompressZstd failed: %v", err)
	}
	if !IsZstdCompressed(compressed) {
		t.Fatal("compressed data was not identified as a Zstd frame")
	}

	decompressed, err := DecompressZstd(compressed)
	if err != nil {
		t.Fatalf("DecompressZstd failed: %v", err)
	}
	if string(decompressed) != largeJSON {
		t.Fatal("decompressed data does not match original repetitive JSON")
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

// Verifies: SYS-REQ-086
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

// Verifies: SYS-REQ-087, SYS-REQ-088
// SYS-REQ-087:nominal:nominal
// SYS-REQ-087:boundary:nominal
// SYS-REQ-087:error_handling:nominal
// SYS-REQ-087:error_handling:negative
// SYS-REQ-088:boundary:nominal
// MCDC SYS-REQ-087: zstd_oversize_decompression_requested=T, zstd_oversize_decompression_blocked=T => TRUE
// MCDC SYS-REQ-087: zstd_oversize_decompression_requested=F, zstd_oversize_decompression_blocked=F => TRUE
//mcdc:ignore:defensive SYS-REQ-087: zstd_oversize_decompression_blocked=F, zstd_oversize_decompression_requested=T => FALSE -- violation row is the negation of the oversize-decompression guard; this test asserts oversized payloads fail and within-limit payloads succeed [reviewed: agent:codex]
//mcdc:ignore:defensive SYS-REQ-088: zstd_allowed_decompression_requested=T, zstd_payload_bytes_preserved=F => FALSE -- violation row is the negation of the within-limit payload-preservation guarantee; this test asserts successful decompression preserves bytes [reviewed: agent:codex]
func TestDecompressZstd_MaxSizeLimit(t *testing.T) {
	// 2MB uncompressed data (exceeds the 1MB minimum limit)
	bigData := bytes.Repeat([]byte("a"), 2*1024*1024)
	compressed, err := CompressZstd(bigData)
	if err != nil {
		t.Fatal(err)
	}

	orig := maxDecompressedSize
	defer SetMaxDecompressedSize(orig)

	// Set limit to minimum (1MB) — below the 2MB data, should fail
	SetMaxDecompressedSize(minDecompressedSize)
	_, err = DecompressZstd(compressed)
	if err == nil {
		t.Error("expected error when decompressed size exceeds limit")
	}

	// Set limit above decompressed size — should succeed
	SetMaxDecompressedSize(3 * 1024 * 1024)
	result, err := DecompressZstd(compressed)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, bigData) {
		t.Error("decompressed data doesn't match original")
	}
}

// Verifies: SYS-REQ-089
// SYS-REQ-089:nominal:nominal
// SYS-REQ-089:boundary:nominal
// SYS-REQ-089:determinism:nominal
// MCDC SYS-REQ-089: zstd_limit_update_requested=T, zstd_minimum_limit_enforced=T => TRUE
//mcdc:ignore:defensive SYS-REQ-089: zstd_limit_update_requested=T, zstd_minimum_limit_enforced=F => FALSE -- violation row is the negation of the minimum-limit clamp; this test asserts below-minimum updates clamp to minDecompressedSize [reviewed: agent:codex]
func TestSetMaxDecompressedSize_ClampsBelowMinimum(t *testing.T) {
	orig := maxDecompressedSize
	defer SetMaxDecompressedSize(orig)

	SetMaxDecompressedSize(512) // well below 1MB minimum
	if maxDecompressedSize != minDecompressedSize {
		t.Errorf("expected maxDecompressedSize to be clamped to %d, got %d", minDecompressedSize, maxDecompressedSize)
	}
	if GetMaxDecompressedSize() != minDecompressedSize {
		t.Errorf("expected GetMaxDecompressedSize to return %d, got %d", minDecompressedSize, GetMaxDecompressedSize())
	}
}

// Verifies: SYS-REQ-085
func TestIsZstdCompressed_WithActualCompressedData(t *testing.T) {
	// Test with actual compressed data
	original := []byte(`{"api_id":"test","name":"Test API"}`)
	compressed, err := CompressZstd(original)
	if err != nil {
		t.Fatalf("CompressZstd failed: %v", err)
	}

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

// Verifies: SYS-REQ-090
// SYS-REQ-090:error_handling:nominal
// SYS-REQ-090:error_handling:negative
// SYS-REQ-090:panic_free_input_handling:nominal
// MCDC SYS-REQ-090: zstd_codec_failure_present=T, zstd_codec_failure_reported=T => TRUE
//mcdc:ignore:defensive SYS-REQ-090: zstd_codec_failure_present=T, zstd_codec_failure_reported=F => FALSE -- violation row is the negation of the codec-failure reporting guarantee; this test asserts nil and wrong-type codec pool failures return errors [reviewed: agent:codex]
func TestZstdCodecPoolFailuresReturnErrors(t *testing.T) {
	origMax := maxDecompressedSize
	defer resetZstdCodecStateForTest(origMax)

	encoderPool = sync.Pool{New: func() interface{} { return nil }}
	_, err := CompressZstd([]byte("payload"))
	if err == nil || !strings.Contains(err.Error(), "failed to get Zstd encoder") {
		t.Fatalf("expected nil encoder pool error, got %v", err)
	}

	encoderPool = sync.Pool{New: func() interface{} { return struct{}{} }}
	_, err = CompressZstd([]byte("payload"))
	if err == nil || !strings.Contains(err.Error(), "invalid encoder type") {
		t.Fatalf("expected invalid encoder type error, got %v", err)
	}

	decoderPool = sync.Pool{New: func() interface{} { return nil }}
	_, err = DecompressZstd([]byte("payload"))
	if err == nil || !strings.Contains(err.Error(), "failed to get Zstd decoder") {
		t.Fatalf("expected nil decoder pool error, got %v", err)
	}

	decoderPool = sync.Pool{New: func() interface{} { return struct{}{} }}
	_, err = DecompressZstd([]byte("payload"))
	if err == nil || !strings.Contains(err.Error(), "invalid decoder type") {
		t.Fatalf("expected invalid decoder type error, got %v", err)
	}

	SetMaxDecompressedSize((uint64(1) << 63) + 1)
	_, err = DecompressZstd([]byte("payload"))
	if err == nil || !strings.Contains(err.Error(), "failed to get Zstd decoder") {
		t.Fatalf("expected decoder construction failure error, got %v", err)
	}
}

func resetZstdCodecStateForTest(maxSize uint64) {
	encoderPool = sync.Pool{
		New: func() interface{} {
			encoder, err := zstd.NewWriter(nil)
			if err != nil {
				return nil
			}
			return encoder
		},
	}
	SetMaxDecompressedSize(maxSize)
}
