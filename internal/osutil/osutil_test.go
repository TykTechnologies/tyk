package osutil_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/osutil"
)

// setupTestDir creates a temporary directory for testing and returns its path.
// It uses t.Cleanup to automatically remove the directory after the test.
func setupTestDir(t *testing.T) string {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "osutil-test-*")
	assert.NoError(t, err, "Failed to create temp directory")

	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	return tempDir
}

// Verifies: SYS-REQ-098, SYS-REQ-099
// SYS-REQ-098:nominal:nominal
// SYS-REQ-098:boundary:nominal
// SYS-REQ-098:determinism:nominal
// SYS-REQ-099:nominal:nominal
// SYS-REQ-099:malformed_input:nominal
// SYS-REQ-099:malformed_input:negative
// SYS-REQ-099:error_handling:nominal
// SYS-REQ-099:error_handling:negative
// MCDC SYS-REQ-098: root_creation_requested=T, root_directory_scoped=T => TRUE
// MCDC SYS-REQ-098: root_creation_requested=T, root_directory_scoped=F => FALSE
// MCDC SYS-REQ-099: invalid_root_path_presented=F, invalid_root_path_rejected=F => TRUE
// MCDC SYS-REQ-099: invalid_root_path_presented=T, invalid_root_path_rejected=T => TRUE
//mcdc:ignore SYS-REQ-099: invalid_root_path_presented=T, invalid_root_path_rejected=F => FALSE -- violation row is the negation of the invalid-root rejection guarantee; this test asserts non-existent and file paths are rejected [category: defensive] [reviewed: agent:codex]
func TestNewRoot(t *testing.T) {
	t.Run("ValidDirectory", func(t *testing.T) {
		tempDir := setupTestDir(t)

		root, err := osutil.NewRoot(tempDir)
		assert.NoError(t, err, "Should not return an error for a valid directory")
		assert.NotNil(t, root, "Should return a non-nil Root instance")
	})

	t.Run("NonExistentPath", func(t *testing.T) {
		nonExistentPath := filepath.Join(os.TempDir(), "this-should-not-exist-12345")
		root, err := osutil.NewRoot(nonExistentPath)
		assert.Error(t, err, "Should return an error for a non-existent path")
		assert.Nil(t, root, "Should not return a Root instance on error")
	})

	t.Run("PathIsAFile", func(t *testing.T) {
		tempDir := setupTestDir(t)

		tempFile, err := os.CreateTemp(tempDir, "test-file-*")
		assert.NoError(t, err)
		tempFile.Close()

		root, err := osutil.NewRoot(tempFile.Name())
		assert.Error(t, err, "Should return an error when path is a file")
		assert.Contains(t, err.Error(), "is not a directory")
		assert.Nil(t, root, "Should not return a Root instance on error")
	})
}

// Verifies: SYS-REQ-100, SYS-REQ-101
// SYS-REQ-100:nominal:nominal
// SYS-REQ-100:boundary:nominal
// SYS-REQ-100:determinism:nominal
// SYS-REQ-101:nominal:nominal
// SYS-REQ-101:malformed_input:nominal
// SYS-REQ-101:malformed_input:negative
// SYS-REQ-101:boundary:nominal
// MCDC SYS-REQ-100: scoped_path_resolution_requested=T, scoped_path_returned=T => TRUE
// MCDC SYS-REQ-100: scoped_path_resolution_requested=T, scoped_path_returned=F => FALSE
// MCDC SYS-REQ-101: lexical_escape_path_presented=F, lexical_escape_rejected=F => TRUE
// MCDC SYS-REQ-101: lexical_escape_path_presented=T, lexical_escape_rejected=T => TRUE
//mcdc:ignore SYS-REQ-101: lexical_escape_path_presented=T, lexical_escape_rejected=F => FALSE -- violation row is the negation of the lexical-escape rejection guarantee; this test asserts escape paths are rejected [category: defensive] [reviewed: agent:codex]
func TestEnsure(t *testing.T) {
	tempDir := setupTestDir(t)
	root, err := osutil.NewRoot(tempDir)
	assert.NoError(t, err)

	t.Run("ValidPath", func(t *testing.T) {
		relPath := "safe/file.txt"
		fullPath, err := root.Ensure(relPath)
		assert.NoError(t, err)
		expectedPath := filepath.Join(tempDir, relPath)
		assert.Equal(t, expectedPath, fullPath)
	})

	t.Run("RootPath", func(t *testing.T) {
		fullPath, err := root.Ensure(".")
		assert.NoError(t, err)
		assert.Equal(t, tempDir, fullPath)
	})

	t.Run("FilesystemRootKeepsSeparator", func(t *testing.T) {
		root, err := osutil.NewRoot(string(os.PathSeparator))
		assert.NoError(t, err)

		fullPath, err := root.Ensure("tmp")
		assert.NoError(t, err)
		assert.Equal(t, filepath.Join(string(os.PathSeparator), "tmp"), fullPath)
	})

	t.Run("PathTraversalAttack", func(t *testing.T) {
		relPath := "../../../etc/passwd"
		fullPath, err := root.Ensure(relPath)
		assert.Error(t, err)
		assert.Empty(t, fullPath)
		assert.Contains(t, err.Error(), "attempts to escape root directory")
	})

	t.Run("PathTraversalAttack by similar name", func(t *testing.T) {
		_, file := filepath.Split(tempDir)
		attackFile := fmt.Sprintf("../%s-wrong", file)

		ensured, err := root.Ensure(attackFile)
		assert.Error(t, err)
		assert.Equal(t, "", ensured)
	})
}

// Verifies: SYS-REQ-102
// SYS-REQ-102:nominal:nominal
// SYS-REQ-102:boundary:nominal
// SYS-REQ-102:error_handling:nominal
// MCDC SYS-REQ-102: scoped_file_operation_requested=T, scoped_file_operation_confined=T => TRUE
func TestWriteFile(t *testing.T) {
	tempDir := setupTestDir(t)
	root, err := osutil.NewRoot(tempDir)
	assert.NoError(t, err)

	t.Run("SuccessfulWrite", func(t *testing.T) {
		fileName := "test.txt"
		content := []byte("hello world")
		perm := os.FileMode(0644)

		err = root.WriteFile(fileName, content, perm)
		assert.NoError(t, err, "WriteFile should not return an error")

		fullPath := filepath.Join(tempDir, fileName)
		readContent, err := os.ReadFile(fullPath)
		assert.NoError(t, err)
		assert.Equal(t, content, readContent)
	})

	t.Run("PathTraversalAttack", func(t *testing.T) {
		err := root.WriteFile("../../../etc/passwd", []byte("blocked"), 0644)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "attempts to escape root directory")
	})
}

// Verifies: SYS-REQ-102
// SYS-REQ-102:error_handling:negative
func TestRemove(t *testing.T) {
	tempDir := setupTestDir(t)
	root, err := osutil.NewRoot(tempDir)
	assert.NoError(t, err)

	t.Run("SuccessfulRemove", func(t *testing.T) {
		fileName := "to_be_removed.txt"
		filePath := filepath.Join(tempDir, fileName)
		err := os.WriteFile(filePath, []byte("delete me"), 0644)
		assert.NoError(t, err)
		assert.FileExists(t, filePath)

		err = root.Remove(fileName)
		assert.NoError(t, err)
		assert.NoFileExists(t, filePath)
	})

	t.Run("PathTraversalAttack", func(t *testing.T) {
		err := root.Remove("../../../etc/passwd")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "attempts to escape root directory")
	})
}

// Verifies: SYS-REQ-102
// SYS-REQ-102:error_handling:negative
func TestStat(t *testing.T) {
	tempDir := setupTestDir(t)
	root, err := osutil.NewRoot(tempDir)
	assert.NoError(t, err)

	t.Run("SuccessfulStat", func(t *testing.T) {
		fileName := "stat_me.txt"
		content := []byte("some data")
		filePath := filepath.Join(tempDir, fileName)
		err := os.WriteFile(filePath, content, 0644)
		assert.NoError(t, err)

		info, err := root.Stat(fileName)
		assert.NoError(t, err)
		assert.NotNil(t, info)
		assert.Equal(t, fileName, info.Name())
		assert.Equal(t, int64(len(content)), info.Size())
	})

	t.Run("PathTraversalAttack", func(t *testing.T) {
		info, err := root.Stat("../../../etc/passwd")
		assert.Error(t, err)
		assert.Nil(t, info)
		assert.Contains(t, err.Error(), "attempts to escape root directory")
	})

	t.Run("FileDoesNotExist", func(t *testing.T) {
		info, err := root.Stat("non_existent_file.txt")
		assert.Error(t, err)
		assert.True(t, os.IsNotExist(err))
		assert.Nil(t, info)
	})
}

// Reproduces: KI-OSUTIL-SYMLINK-ESCAPE
// Verifies: SYS-REQ-102
// MCDC SYS-REQ-102: scoped_file_operation_requested=T, scoped_file_operation_confined=F => FALSE
func TestKnownIssue_WriteFileFollowsSymlinkOutsideRoot(t *testing.T) {
	tempDir := setupTestDir(t)
	outsideDir := setupTestDir(t)
	outsideFile := filepath.Join(outsideDir, "outside.txt")
	err := os.WriteFile(outsideFile, []byte("original"), 0644)
	assert.NoError(t, err)

	linkPath := filepath.Join(tempDir, "link.txt")
	err = os.Symlink(outsideFile, linkPath)
	if err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}

	root, err := osutil.NewRoot(tempDir)
	assert.NoError(t, err)

	err = root.WriteFile("link.txt", []byte("changed"), 0644)
	assert.NoError(t, err)

	outsideContent, err := os.ReadFile(outsideFile)
	assert.NoError(t, err)
	assert.Equal(t, []byte("changed"), outsideContent)
}
