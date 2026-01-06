package gateway

import (
	"testing"

	"github.com/TykTechnologies/tyk/config"
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

func TestRoundTripSaveAndLoad(t *testing.T) {
	tests := []struct {
		name               string
		compressionEnabled bool
		apiID              string
		inputJSON          string
	}{
		{
			name:               "With compression enabled",
			compressionEnabled: true,
			apiID:              "test-compressed",
			inputJSON:          `[{"api_id":"test-compressed","name":"Test API","proxy":{"listen_path":"/test","target_url":"http://example.com"}}]`,
		},
		{
			name:               "With compression disabled",
			compressionEnabled: false,
			apiID:              "test-uncompressed",
			inputJSON:          `[{"api_id":"test-uncompressed","name":"Test API","proxy":{"listen_path":"/test","target_url":"http://example.com"}}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := StartTest(func(globalConf *config.Config) {
				globalConf.Storage.CompressAPIDefinitions = tt.compressionEnabled
			})
			defer ts.Close()

			err := ts.Gw.saveRPCDefinitionsBackup(tt.inputJSON)
			if err != nil {
				t.Fatalf("Failed to save backup: %v", err)
			}

			specs, err := ts.Gw.LoadDefinitionsFromRPCBackup()
			if err != nil {
				t.Fatalf("Failed to load backup: %v", err)
			}

			if len(specs) != 1 {
				t.Errorf("Expected 1 API spec, got %d", len(specs))
			}

			if len(specs) > 0 && specs[0].APIID != tt.apiID {
				t.Errorf("Expected API ID %q, got %q", tt.apiID, specs[0].APIID)
			}
		})
	}
}

func TestBackwardCompatibility(t *testing.T) {
	tests := []struct {
		name            string
		saveCompression bool
		loadCompression bool
		apiID           string
		inputJSON       string
	}{
		{
			name:            "Load uncompressed with compression enabled",
			saveCompression: false,
			loadCompression: true,
			apiID:           "test-backward",
			inputJSON:       `[{"api_id":"test-backward","name":"Test API","proxy":{"listen_path":"/test","target_url":"http://example.com"}}]`,
		},
		{
			name:            "Load compressed with compression disabled",
			saveCompression: true,
			loadCompression: false,
			apiID:           "test-forward",
			inputJSON:       `[{"api_id":"test-forward","name":"Test API","proxy":{"listen_path":"/test","target_url":"http://example.com"}}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save with first configuration
			ts1 := StartTest(func(globalConf *config.Config) {
				globalConf.Storage.CompressAPIDefinitions = tt.saveCompression
			})
			defer ts1.Close()

			err := ts1.Gw.saveRPCDefinitionsBackup(tt.inputJSON)
			if err != nil {
				t.Fatalf("Failed to save backup: %v", err)
			}

			// Load with second configuration
			ts2 := StartTest(func(globalConf *config.Config) {
				globalConf.Storage.CompressAPIDefinitions = tt.loadCompression
			})
			defer ts2.Close()

			specs, err := ts2.Gw.LoadDefinitionsFromRPCBackup()
			if err != nil {
				t.Fatalf("Failed to load backup: %v", err)
			}

			if len(specs) != 1 {
				t.Errorf("Expected 1 API spec, got %d", len(specs))
			}

			if len(specs) > 0 && specs[0].APIID != tt.apiID {
				t.Errorf("Expected API ID %q, got %q", tt.apiID, specs[0].APIID)
			}
		})
	}
}

// generateAPIDefinition creates an API definition JSON of specified size
func generateAPIDefinition(apiID string, targetSizeKB int) string {
	// Base API definition structure
	base := `{"api_id":"` + apiID + `","name":"Benchmark API","proxy":{"listen_path":"/bench","target_url":"http://example.com"},"version_data":{"versions":{"v1":{"name":"v1"}}},"description":"`

	// Calculate padding needed to reach target size
	baseSize := len(base) + len(`"}}}`)
	paddingSize := (targetSizeKB * 1024) - baseSize

	if paddingSize < 0 {
		paddingSize = 0
	}

	// Generate padding string
	padding := ""
	for i := 0; i < paddingSize; i++ {
		padding += "x"
	}

	return base + padding + `"}}`
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
			inputJSON := `[` + apiDef + `]`

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

// BenchmarkLoadDefinitionsFromRPCBackup benchmarks the load operation with various sizes
func BenchmarkLoadDefinitionsFromRPCBackup(b *testing.B) {
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

			// Generate and save test data
			apiDef := generateAPIDefinition("bench-api", bm.sizeKB)
			inputJSON := `[` + apiDef + `]`

			err := ts.Gw.saveRPCDefinitionsBackup(inputJSON)
			if err != nil {
				b.Fatalf("Failed to save backup: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				specs, err := ts.Gw.LoadDefinitionsFromRPCBackup()
				if err != nil {
					b.Fatalf("Failed to load backup: %v", err)
				}
				if len(specs) != 1 {
					b.Fatalf("Expected 1 spec, got %d", len(specs))
				}
			}

			// Report size metrics
			b.ReportMetric(float64(len(inputJSON))/1024, "input_KB")
		})
	}
}

// BenchmarkRoundTrip benchmarks the complete save and load cycle
func BenchmarkRoundTrip(b *testing.B) {
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
			inputJSON := `[` + apiDef + `]`

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Save
				err := ts.Gw.saveRPCDefinitionsBackup(inputJSON)
				if err != nil {
					b.Fatalf("Failed to save backup: %v", err)
				}

				// Load
				specs, err := ts.Gw.LoadDefinitionsFromRPCBackup()
				if err != nil {
					b.Fatalf("Failed to load backup: %v", err)
				}
				if len(specs) != 1 {
					b.Fatalf("Expected 1 spec, got %d", len(specs))
				}
			}

			// Report size metrics
			b.ReportMetric(float64(len(inputJSON))/1024, "input_KB")
		})
	}
}
