package osutil_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/TykTechnologies/tyk/internal/osutil"
	"github.com/stretchr/testify/assert"
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

func TestWriteFile(t *testing.T) {
	tempDir := setupTestDir(t)
	root, err := osutil.NewRoot(tempDir)
	assert.NoError(t, err)

	fileName := "test.txt"
	content := []byte("hello world")
	perm := os.FileMode(0644)

	err = root.WriteFile(fileName, content, perm)
	assert.NoError(t, err, "WriteFile should not return an error")

	fullPath := filepath.Join(tempDir, fileName)
	readContent, err := os.ReadFile(fullPath)
	assert.NoError(t, err)
	assert.Equal(t, content, readContent)
}

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
