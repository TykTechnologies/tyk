package sanitize

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Verifies: SYS-REQ-091, SYS-REQ-092
// SYS-REQ-091:nominal:nominal
// SYS-REQ-091:boundary:nominal
// SYS-REQ-091:encoding_safety:nominal
// SYS-REQ-091:determinism:nominal
// SYS-REQ-092:nominal:nominal
// SYS-REQ-092:malformed_input:nominal
// SYS-REQ-092:malformed_input:negative
// SYS-REQ-092:error_handling:nominal
// SYS-REQ-092:error_handling:negative
// SYS-REQ-092:boundary:nominal
// SYS-REQ-092:encoding_safety:nominal
// MCDC SYS-REQ-091: archive_path_validation_requested=T, archive_path_within_target=T => TRUE
// MCDC SYS-REQ-091: archive_path_validation_requested=T, archive_path_within_target=F => FALSE
// MCDC SYS-REQ-092: unsafe_archive_path_presented=T, unsafe_archive_path_rejected=T => TRUE
func TestZipFilePath(t *testing.T) {
	targetDir := "/tmp/bundles/test-bundle"

	tests := []struct {
		filePath    string
		targetDir   string
		wantErr     bool
		errContains error
	}{
		{
			filePath:  "middleware.js",
			targetDir: targetDir,
			wantErr:   false,
		},
		{
			filePath:  "lib/utils.js",
			targetDir: targetDir,
			wantErr:   false,
		},
		{
			filePath:  "config.test.js",
			targetDir: targetDir,
			wantErr:   false,
		},
		{
			filePath:    "/test/path",
			targetDir:   targetDir,
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			filePath:    "../../test/path",
			targetDir:   targetDir,
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			filePath:    "invalid/../../test/path",
			targetDir:   targetDir,
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			filePath:    "./../test",
			targetDir:   targetDir,
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			filePath:  "./middleware.js",
			targetDir: targetDir,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.filePath, func(t *testing.T) {
			err := ZipFilePath(tt.filePath, tt.targetDir)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != nil {
					assert.ErrorIs(t, err, tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Reproduces: KI-SANITIZE-WINDOWS-VOLUME-PATH
// Verifies: SYS-REQ-092
// MCDC SYS-REQ-092: unsafe_archive_path_presented=T, unsafe_archive_path_rejected=F => FALSE
func TestKnownIssue_ZipFilePathAcceptsWindowsVolumePathOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows filepath semantics reject the volume-qualified archive path")
	}

	err := ZipFilePath(`C:\Windows\System32`, "/tmp/bundles/test-bundle")
	assert.NoError(t, err)
}

// Verifies: SYS-REQ-093, SYS-REQ-094
// SYS-REQ-093:nominal:nominal
// SYS-REQ-093:boundary:nominal
// SYS-REQ-093:encoding_safety:nominal
// SYS-REQ-093:determinism:nominal
// SYS-REQ-094:nominal:nominal
// SYS-REQ-094:malformed_input:nominal
// SYS-REQ-094:malformed_input:negative
// SYS-REQ-094:error_handling:nominal
// SYS-REQ-094:error_handling:negative
// SYS-REQ-094:boundary:nominal
// SYS-REQ-094:encoding_safety:nominal
// MCDC SYS-REQ-093: path_component_validation_requested=T, path_component_accepted=T => TRUE
// MCDC SYS-REQ-093: path_component_validation_requested=T, path_component_accepted=F => FALSE
// MCDC SYS-REQ-094: unsafe_path_component_presented=T, unsafe_path_component_rejected=T => TRUE
func TestValidatePathComponent(t *testing.T) {
	tests := []struct {
		name        string
		component   string
		wantErr     bool
		errContains error
	}{
		{
			name:      "valid uuid hex",
			component: "c92bb15331a049f68e6d8a6dafaa8243",
			wantErr:   false,
		},
		{
			name:      "valid simple filename",
			component: "api-definition",
			wantErr:   false,
		},
		{
			name:      "valid filename with extension",
			component: "config.json",
			wantErr:   false,
		},
		{
			name:      "valid filename with dashes and underscores",
			component: "test-api_v1",
			wantErr:   false,
		},
		{
			name:        "empty string",
			component:   "",
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			name:        "dot",
			component:   ".",
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			name:        "double dot",
			component:   "..",
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			name:        "path traversal with relative path",
			component:   "../../../etc/passwd",
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			name:        "path traversal with forward slash",
			component:   "../../sensitive-file",
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			name:        "absolute path unix",
			component:   "/etc/passwd",
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			name:        "absolute path windows",
			component:   "C:\\Windows\\System32",
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			name:        "contains forward slash",
			component:   "some/path/file",
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			name:        "contains backslash",
			component:   "some\\path\\file",
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			name:        "hidden path traversal",
			component:   "valid/../../../etc/passwd",
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			name:        "url encoded dot dot",
			component:   "%2e%2e",
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			name:        "url encoded dot",
			component:   "%2e",
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			name:        "url encoded slash",
			component:   "safe%2Ffile",
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
		{
			name:        "double encoded traversal",
			component:   "%252e%252e",
			wantErr:     true,
			errContains: ErrInvalidFilePath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePathComponent(tt.component)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != nil {
					assert.ErrorIs(t, err, tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Reproduces: KI-SANITIZE-MALFORMED-PERCENT
// Verifies: SYS-REQ-094
// MCDC SYS-REQ-094: unsafe_path_component_presented=T, unsafe_path_component_rejected=F => FALSE
func TestKnownIssue_ValidatePathComponentAcceptsMalformedPercentEscape(t *testing.T) {
	err := ValidatePathComponent("safe%2")
	assert.NoError(t, err)
}

// Verifies: SYS-REQ-093, SYS-REQ-094
// MCDC SYS-REQ-094: unsafe_path_component_presented=F, unsafe_path_component_rejected=F => TRUE
func TestValidatePathComponent_DecodingLimit(t *testing.T) {
	component := "api-definition"
	for i := 0; i < 3; i++ {
		component = strings.ReplaceAll(component, "-", "%2D")
	}
	if err := ValidatePathComponent(component); err != nil {
		t.Fatalf("expected triply encoded safe component to pass, got %v", err)
	}

	if filepath.Base("safe/file") == "safe/file" {
		t.Fatal("test platform does not treat forward slash as a path separator")
	}
}
