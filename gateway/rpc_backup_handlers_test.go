package gateway

import (
	"strings"
	"testing"

	persistentmodel "github.com/TykTechnologies/storage/persistent/model"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/compression"
)

func TestSaveRPCDefinitionsBackup(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     bool
		expectedErr string
	}{
		{
			name:        "Invalid JSON",
			input:       `not json at all`,
			wantErr:     true,
			expectedErr: "--> RPC Backup save failure: wrong format, skipping.",
		},
		{
			name:    "Valid JSON array",
			input:   `[{"api_id":"test","name":"Test API"}]`,
			wantErr: false,
		},
		{
			name:    "Empty array",
			input:   `[]`,
			wantErr: false,
		},
		{
			name:    "Valid JSON object",
			input:   `{"api_id":"test","name":"Test API"}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			err := ts.Gw.saveRPCDefinitionsBackup(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.expectedErr != "" && err.Error() != tt.expectedErr {
					t.Errorf("Expected error %q, got %q", tt.expectedErr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			}
		})
	}
}

// generateAPIDefinition creates an API definition JSON of specified size
func generateAPIDefinition(apiID string, targetSizeKB int) string {
	// Base API definition with required fields
	base := `{"api_id":"` + apiID + `","name":"Benchmark API","proxy":{"listen_path":"/bench","target_url":"http://example.com"},"version_data":{"not_versioned":true,"versions":{"Default":{"name":"Default"}}},"description":"`

	// Calculate padding needed to reach target size
	baseSize := len(base) + len(`"}`)
	paddingSize := (targetSizeKB * 1024) - baseSize

	if paddingSize < 0 {
		paddingSize = 0
	}

	// Generate padding string using optimized strings.Repeat
	padding := strings.Repeat("x", paddingSize)

	return base + padding + `"}`
}

// BenchmarkSaveRPCDefinitionsBackup benchmarks the save operation with various sizes
func BenchmarkSaveRPCDefinitionsBackup(b *testing.B) {
	benchmarks := []struct {
		name               string
		sizeKB             int
		compressionEnabled bool
	}{
		{"Small_10KB_Uncompressed", 10, false},
		{"Small_10KB_Compressed", 10, true},
		{"Medium_100KB_Uncompressed", 100, false},
		{"Medium_100KB_Compressed", 100, true},
		{"Large_1MB_Uncompressed", 1024, false},
		{"Large_1MB_Compressed", 1024, true},
		{"ExtraLarge_5MB_Uncompressed", 5120, false},
		{"ExtraLarge_5MB_Compressed", 5120, true},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			ts := StartTest(func(globalConf *config.Config) {
				globalConf.Storage.CompressAPIDefinitions = bm.compressionEnabled
			})
			defer ts.Close()

			// Generate test data
			apiDef := generateAPIDefinition("bench-api", bm.sizeKB)
			inputJSON := `[{"api_definition":` + apiDef + `}]`

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				err := ts.Gw.saveRPCDefinitionsBackup(inputJSON)
				if err != nil {
					b.Fatalf("Failed to save backup: %v", err)
				}
			}

			// Report size metrics
			b.ReportMetric(float64(len(inputJSON))/1024, "input_KB")
		})
	}
}

// runDecompressBackupTests is a shared helper that runs the full decompression
// test suite against any backup kind. It is used by both TestDecompressAPIBackup
// and TestDecompressPolicyBackup to avoid duplicating identical test logic.
//
// decompress is the bound method under test (e.g. ts.Gw.decompressAPIBackup).
// enableCompress is a config setup func that enables compression for the kind
// under test, used when starting a gateway for the round-trip subtest.
// getCompress returns the matching compress method from a given gateway, also
// used in the round-trip subtest.
func runDecompressBackupTests(
	t *testing.T,
	decompress func(string) (string, error),
	enableCompress func(*config.Config),
	getCompress func(*Gateway) func(string) string,
) {
	t.Helper()

	tests := []struct {
		name        string
		input       string
		wantErr     bool
		expectedErr string
		expected    string
	}{
		{
			name:     "Uncompressed data",
			input:    `[{"id":"test","name":"Test"}]`,
			wantErr:  false,
			expected: `[{"id":"test","name":"Test"}]`,
		},
		{
			name:     "Empty uncompressed data",
			input:    `[]`,
			wantErr:  false,
			expected: `[]`,
		},
		{
			name:     "Invalid zstd data (wrong magic bytes)",
			input:    "hello", // Plain text, not valid zstd
			wantErr:  false,   // Should be treated as uncompressed JSON
			expected: "hello",
		},
		{
			name:        "Corrupt compressed data (valid magic bytes, invalid payload)",
			input:       string([]byte{0x28, 0xB5, 0x2F, 0xFD}) + "this is not valid zstd data",
			wantErr:     true,
			expectedErr: "[RPC] --> Failed to decompress",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := decompress(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.expectedErr != "" && !strings.Contains(err.Error(), tt.expectedErr) {
					t.Errorf("Expected error containing %q, got %q", tt.expectedErr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if result != tt.expected {
					t.Errorf("Expected result %q, got %q", tt.expected, result)
				}
			}
		})
	}

	t.Run("Compressed data round-trip", func(t *testing.T) {
		ts := StartTest(enableCompress)
		defer ts.Close()

		original := `[{"id":"test","name":"Test","description":"This is a test"}]`
		compress := getCompress(ts.Gw)

		compressed := compress(original)

		// Verify it has Zstd magic bytes
		compressedBytes := []byte(compressed)
		if len(compressedBytes) < 4 {
			t.Fatalf("Compressed data is too short: %d bytes", len(compressedBytes))
		}

		expectedMagic := []byte{0x28, 0xB5, 0x2F, 0xFD}
		for i := 0; i < 4; i++ {
			if compressedBytes[i] != expectedMagic[i] {
				t.Errorf("Magic byte at position %d: got 0x%02X, want 0x%02X", i, compressedBytes[i], expectedMagic[i])
			}
		}

		// Decompress it back and verify round-trip fidelity
		decompressed, err := decompress(compressed)
		if err != nil {
			t.Fatalf("Failed to decompress: %v", err)
		}

		if decompressed != original {
			t.Errorf("Round-trip failed. Expected %q, got %q", original, decompressed)
		}
	})

	t.Run("Compressed data exceeds max decompressed size", func(t *testing.T) {
		// SetMaxDecompressedSize clamps to a 1MB minimum, so the payload must exceed 1MB.
		// A string of repeated characters compresses very efficiently, meaning the stored
		// blob is tiny but decompression is aborted once the output crosses the limit.
		originalMaxSize := compression.GetMaxDecompressedSize()
		compression.SetMaxDecompressedSize(1 * 1024 * 1024)
		defer compression.SetMaxDecompressedSize(originalMaxSize)

		largePayload := strings.Repeat("a", 1*1024*1024+1)
		compressed, err := compression.CompressZstd([]byte(largePayload))
		if err != nil {
			t.Fatalf("Failed to compress test payload: %v", err)
		}

		_, err = decompress(string(compressed))
		if err == nil {
			t.Fatal("Expected error for payload exceeding max decompressed size, got nil")
		}
		if !strings.Contains(err.Error(), "Failed to decompress") {
			t.Errorf("Expected decompression failure error, got: %v", err)
		}
	})
}

func TestDecompressAPIBackup(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	runDecompressBackupTests(
		t,
		ts.Gw.decompressAPIBackup,
		func(c *config.Config) { c.Storage.CompressAPIDefinitions = true },
		func(gw *Gateway) func(string) string { return gw.compressAPIBackup },
	)
}

func TestLoadRPCDefinitionsBackup(t *testing.T) {
	t.Run("Load from backup - uncompressed", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		objectID := persistentmodel.NewObjectID()

		// First save a backup
		apiJSON := `[{"api_definition":{"id":"` + objectID.Hex() + `","name":"Test API","api_id":"test-api","org_id":"test-org","proxy":{"listen_path":"/test/","target_url":"http://example.com"},"version_data":{"not_versioned":true,"versions":{"Default":{"name":"Default"}}}}}]`

		err := ts.Gw.saveRPCDefinitionsBackup(apiJSON)
		if err != nil {
			t.Fatalf("Failed to save backup: %v", err)
		}

		// Now load it back
		specs, err := ts.Gw.LoadDefinitionsFromRPCBackup()
		if err != nil {
			t.Fatalf("Failed to load backup: %v", err)
		}

		if len(specs) != 1 {
			t.Fatalf("Expected 1 spec, got %d", len(specs))
		}

		if specs[0].APIID != "test-api" {
			t.Errorf("Expected APIID 'test-api', got %q", specs[0].APIID)
		}
		if specs[0].Name != "Test API" {
			t.Errorf("Expected Name 'Test API', got %q", specs[0].Name)
		}
	})

	t.Run("Load from backup - compressed", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.Storage.CompressAPIDefinitions = true
		})
		defer ts.Close()

		objectID := persistentmodel.NewObjectID()

		// Save a backup with compression enabled
		apiJSON := `[{"api_definition":{"id":"` + objectID.Hex() + `","name":"Compressed API","api_id":"compressed-api","org_id":"test-org","proxy":{"listen_path":"/compressed/","target_url":"http://example.com"},"version_data":{"not_versioned":true,"versions":{"Default":{"name":"Default"}}}}}]`

		err := ts.Gw.saveRPCDefinitionsBackup(apiJSON)
		if err != nil {
			t.Fatalf("Failed to save compressed backup: %v", err)
		}

		// Load it back
		specs, err := ts.Gw.LoadDefinitionsFromRPCBackup()
		if err != nil {
			t.Fatalf("Failed to load compressed backup: %v", err)
		}

		if len(specs) != 1 {
			t.Fatalf("Expected 1 spec, got %d", len(specs))
		}

		if specs[0].APIID != "compressed-api" {
			t.Errorf("Expected APIID 'compressed-api', got %q", specs[0].APIID)
		}
		if specs[0].Name != "Compressed API" {
			t.Errorf("Expected Name 'Compressed API', got %q", specs[0].Name)
		}
	})

	t.Run("Load from backup - empty backup", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		// Save an empty array
		err := ts.Gw.saveRPCDefinitionsBackup(`[]`)
		if err != nil {
			t.Fatalf("Failed to save empty backup: %v", err)
		}

		// Load it back
		specs, err := ts.Gw.LoadDefinitionsFromRPCBackup()
		if err != nil {
			t.Fatalf("Failed to load empty backup: %v", err)
		}

		if len(specs) != 0 {
			t.Errorf("Expected 0 specs, got %d", len(specs))
		}
	})
}

// BenchmarkLoadRPCDefinitionsBackup benchmarks the load operation with various sizes
func BenchmarkLoadRPCDefinitionsBackup(b *testing.B) {
	benchmarks := []struct {
		name               string
		sizeKB             int
		compressionEnabled bool
	}{
		{"Small_10KB_Uncompressed", 10, false},
		{"Small_10KB_Compressed", 10, true},
		{"Medium_100KB_Uncompressed", 100, false},
		{"Medium_100KB_Compressed", 100, true},
		{"Large_1MB_Uncompressed", 1024, false},
		{"Large_1MB_Compressed", 1024, true},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			ts := StartTest(func(globalConf *config.Config) {
				globalConf.Storage.CompressAPIDefinitions = bm.compressionEnabled
			})
			defer ts.Close()

			// Generate and save test data
			apiDef := generateAPIDefinition("bench-api", bm.sizeKB)
			inputJSON := `[{"api_definition":` + apiDef + `}]`

			err := ts.Gw.saveRPCDefinitionsBackup(inputJSON)
			if err != nil {
				b.Fatalf("Failed to save backup: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := ts.Gw.LoadDefinitionsFromRPCBackup()
				if err != nil {
					b.Fatalf("Failed to load backup: %v", err)
				}
			}

			// Report size metrics
			b.ReportMetric(float64(len(inputJSON))/1024, "input_KB")
		})
	}
}

// generatePolicy creates a policy JSON of specified size
func generatePolicy(policyID string, targetSizeKB int) string {
	base := `{"id":"` + policyID + `","name":"Benchmark Policy","org_id":"test-org","active":true,"description":"`
	baseSize := len(base) + len(`"}`)
	paddingSize := (targetSizeKB * 1024) - baseSize
	if paddingSize < 0 {
		paddingSize = 0
	}
	return base + strings.Repeat("x", paddingSize) + `"}`
}

func TestSaveRPCPoliciesBackup(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     bool
		expectedErr string
	}{
		{
			name:        "Invalid JSON",
			input:       `not json at all`,
			wantErr:     true,
			expectedErr: "--> RPC Backup save failure: wrong format, skipping.",
		},
		{
			name:    "Valid JSON array",
			input:   `[{"id":"test","name":"Test Policy","org_id":"test-org"}]`,
			wantErr: false,
		},
		{
			name:    "Empty array",
			input:   `[]`,
			wantErr: false,
		},
		{
			name:    "Valid JSON object",
			input:   `{"id":"test","name":"Test Policy","org_id":"test-org"}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := StartTest(nil)
			defer ts.Close()

			err := ts.Gw.saveRPCPoliciesBackup(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.expectedErr != "" && err.Error() != tt.expectedErr {
					t.Errorf("Expected error %q, got %q", tt.expectedErr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			}
		})
	}
}

func TestDecompressPolicyBackup(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	runDecompressBackupTests(
		t,
		ts.Gw.decompressPolicyBackup,
		func(c *config.Config) { c.Storage.CompressPolicies = true },
		func(gw *Gateway) func(string) string { return gw.compressPolicyBackup },
	)
}

func TestLoadRPCPoliciesBackup(t *testing.T) {
	t.Run("Load from backup - uncompressed", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		policyJSON := `[{"id":"test-policy","name":"Test Policy","org_id":"test-org"}]`

		err := ts.Gw.saveRPCPoliciesBackup(policyJSON)
		if err != nil {
			t.Fatalf("Failed to save backup: %v", err)
		}

		policies, err := ts.Gw.LoadPoliciesFromRPCBackup()
		if err != nil {
			t.Fatalf("Failed to load backup: %v", err)
		}

		if len(policies) != 1 {
			t.Fatalf("Expected 1 policy, got %d", len(policies))
		}

		if policies[0].ID != "test-policy" {
			t.Errorf("Expected ID 'test-policy', got %q", policies[0].ID)
		}
		if policies[0].Name != "Test Policy" {
			t.Errorf("Expected Name 'Test Policy', got %q", policies[0].Name)
		}
	})

	t.Run("Load from backup - compressed", func(t *testing.T) {
		ts := StartTest(func(globalConf *config.Config) {
			globalConf.Storage.CompressPolicies = true
		})
		defer ts.Close()

		policyJSON := `[{"id":"compressed-policy","name":"Compressed Policy","org_id":"test-org"}]`

		err := ts.Gw.saveRPCPoliciesBackup(policyJSON)
		if err != nil {
			t.Fatalf("Failed to save compressed backup: %v", err)
		}

		policies, err := ts.Gw.LoadPoliciesFromRPCBackup()
		if err != nil {
			t.Fatalf("Failed to load compressed backup: %v", err)
		}

		if len(policies) != 1 {
			t.Fatalf("Expected 1 policy, got %d", len(policies))
		}

		if policies[0].ID != "compressed-policy" {
			t.Errorf("Expected ID 'compressed-policy', got %q", policies[0].ID)
		}
		if policies[0].Name != "Compressed Policy" {
			t.Errorf("Expected Name 'Compressed Policy', got %q", policies[0].Name)
		}
	})

	t.Run("Load from backup - empty backup", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		err := ts.Gw.saveRPCPoliciesBackup(`[]`)
		if err != nil {
			t.Fatalf("Failed to save empty backup: %v", err)
		}

		policies, err := ts.Gw.LoadPoliciesFromRPCBackup()
		if err != nil {
			t.Fatalf("Failed to load empty backup: %v", err)
		}

		if len(policies) != 0 {
			t.Errorf("Expected 0 policies, got %d", len(policies))
		}
	})
}

// BenchmarkSaveRPCPoliciesBackup benchmarks the save operation with various sizes
func BenchmarkSaveRPCPoliciesBackup(b *testing.B) {
	benchmarks := []struct {
		name               string
		sizeKB             int
		compressionEnabled bool
	}{
		{"Small_10KB_Uncompressed", 10, false},
		{"Small_10KB_Compressed", 10, true},
		{"Medium_100KB_Uncompressed", 100, false},
		{"Medium_100KB_Compressed", 100, true},
		{"Large_1MB_Uncompressed", 1024, false},
		{"Large_1MB_Compressed", 1024, true},
		{"ExtraLarge_5MB_Uncompressed", 5120, false},
		{"ExtraLarge_5MB_Compressed", 5120, true},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			ts := StartTest(func(globalConf *config.Config) {
				globalConf.Storage.CompressPolicies = bm.compressionEnabled
			})
			defer ts.Close()

			policy := generatePolicy("bench-policy", bm.sizeKB)
			inputJSON := `[` + policy + `]`

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				err := ts.Gw.saveRPCPoliciesBackup(inputJSON)
				if err != nil {
					b.Fatalf("Failed to save backup: %v", err)
				}
			}

			b.ReportMetric(float64(len(inputJSON))/1024, "input_KB")
		})
	}
}

// BenchmarkLoadRPCPoliciesBackup benchmarks the load operation with various sizes
func BenchmarkLoadRPCPoliciesBackup(b *testing.B) {
	benchmarks := []struct {
		name               string
		sizeKB             int
		compressionEnabled bool
	}{
		{"Small_10KB_Uncompressed", 10, false},
		{"Small_10KB_Compressed", 10, true},
		{"Medium_100KB_Uncompressed", 100, false},
		{"Medium_100KB_Compressed", 100, true},
		{"Large_1MB_Uncompressed", 1024, false},
		{"Large_1MB_Compressed", 1024, true},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			ts := StartTest(func(globalConf *config.Config) {
				globalConf.Storage.CompressPolicies = bm.compressionEnabled
			})
			defer ts.Close()

			policy := generatePolicy("bench-policy", bm.sizeKB)
			inputJSON := `[` + policy + `]`

			err := ts.Gw.saveRPCPoliciesBackup(inputJSON)
			if err != nil {
				b.Fatalf("Failed to save backup: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := ts.Gw.LoadPoliciesFromRPCBackup()
				if err != nil {
					b.Fatalf("Failed to load backup: %v", err)
				}
			}

			b.ReportMetric(float64(len(inputJSON))/1024, "input_KB")
		})
	}
}
