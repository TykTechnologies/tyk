package sanitize

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
