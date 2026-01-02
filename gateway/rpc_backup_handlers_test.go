package gateway

import (
	"encoding/json"
	"testing"

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
			input:       `{"invalid json`,
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

func TestFormatDetection(t *testing.T) {
	tests := []struct {
		name           string
		setupData      func() []byte
		shouldCompress bool
	}{
		{
			name: "Compressed format",
			setupData: func() []byte {
				originalJSON := `[{"api_id":"test","name":"Test API"}]`
				compressed, _ := compression.CompressZstd([]byte(originalJSON))
				return compressed
			},
			shouldCompress: true,
		},
		{
			name: "Uncompressed format",
			setupData: func() []byte {
				return []byte(`[{"api_id":"test","name":"Test API"}]`)
			},
			shouldCompress: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.setupData()

			if tt.shouldCompress {
				// Should be detected as Zstd
				if !compression.IsZstdCompressed(data) {
					t.Error("Compressed data not detected as Zstd")
				}

				// Should decompress successfully
				decompressed, err := compression.DecompressZstd(data)
				if err != nil {
					t.Fatalf("Failed to decompress: %v", err)
				}

				if !json.Valid(decompressed) {
					t.Error("Decompressed data is not valid JSON")
				}
			} else {
				// Should not be detected as Zstd
				if compression.IsZstdCompressed(data) {
					t.Error("Plain JSON incorrectly detected as Zstd compressed")
				}

				// Original data should be valid JSON
				if !json.Valid(data) {
					t.Error("Plain JSON should be valid")
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
