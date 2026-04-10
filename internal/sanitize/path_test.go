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
