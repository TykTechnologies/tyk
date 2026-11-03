package goplugin

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockStorage implements storage to simulate which file to load.
// its just a mock
type MockStorage struct {
	files []string
}

func (ms MockStorage) fileExist(path string) bool {
	for _, v := range ms.files {
		// clean path as some of them has ./ as prefix
		path := strings.TrimPrefix(path, "./")
		if v == path {
			return true
		}
	}

	return false
}

func TestGetPluginFileNameToLoad(t *testing.T) {
	// it can be any version, but for testing we will take this one
	gwVersion := getPrefixedVersion()
	gwVersionWithoutPrefix := gwVersion[1:]

	OSandArch := runtime.GOOS + "_" + runtime.GOARCH

	testCases := []struct {
		name             string
		pluginName       string
		files            []string
		expectedFileName string
	}{
		{
			name:             "base name file exist",
			pluginName:       "myplugin.so",
			files:            []string{"myplugin.so", "myplugin", "anything-else"},
			expectedFileName: "myplugin.so",
		},
		{
			name:             "exist plugin file that follows new formatting",
			pluginName:       "myplugin.so",
			files:            []string{"myplugin_" + gwVersion + "_" + OSandArch + ".so", "myplugin_" + gwVersion + "_linux_amd64.so", "myplugin", "anything-else"},
			expectedFileName: "./myplugin_" + gwVersion + "_" + OSandArch + ".so",
		},
		{
			// in some point we had an issue where name loaded didn't contain prefix v. So we keep it for backward compatibility
			name:             "exist plugin file that follows new formatting but gw version without prefix v",
			pluginName:       "myplugin.so",
			files:            []string{"myplugin_" + gwVersionWithoutPrefix + "_" + OSandArch + ".so", "myplugin", "anything-else", "myplugin.so"},
			expectedFileName: "./myplugin_" + gwVersionWithoutPrefix + "_" + OSandArch + ".so",
		},
		{
			name:             "append prefix to gateway version",
			pluginName:       "myplugin.so",
			files:            []string{"myplugin_" + gwVersion + "_" + OSandArch + ".so"},
			expectedFileName: "./myplugin_" + gwVersion + "_" + OSandArch + ".so",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			filenameToLoad, err := GetPluginFileNameToLoad(MockStorage{files: testCase.files}, testCase.pluginName)
			assert.NoError(t, err)
			assert.Equal(t, testCase.expectedFileName, filenameToLoad)
		})
	}
}

// captureLogs routes the package logger through a test hook for the duration
// of the test, restoring the original hooks afterwards.
func captureLogs(t *testing.T) *logrustest.Hook {
	t.Helper()

	original := log.ReplaceHooks(make(logrus.LevelHooks))
	hook := new(logrustest.Hook)
	log.AddHook(hook)

	t.Cleanup(func() { log.ReplaceHooks(original) })

	return hook
}

func entriesAtOrAbove(hook *logrustest.Hook, level logrus.Level) []string {
	var msgs []string
	for _, entry := range hook.AllEntries() {
		if entry.Level <= level {
			msgs = append(msgs, entry.Level.String()+": "+entry.Message)
		}
	}
	return msgs
}

func TestGetPluginFileNameToLoad_MissingCandidatesAreNotWarnings(t *testing.T) {
	gwVersion := getPrefixedVersion()
	osAndArch := runtime.GOOS + "_" + runtime.GOARCH

	testCases := []struct {
		name         string
		existingFile string
	}{
		{
			name:         "only the plain name exists",
			existingFile: "myplugin.so",
		},
		{
			name:         "configured path already carries version, os and arch",
			existingFile: "myplugin_" + gwVersion + "_" + osAndArch + ".so",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pluginPath := filepath.Join(dir, tc.existingFile)
			require.NoError(t, os.WriteFile(pluginPath, []byte("not a real plugin"), 0o600))

			hook := captureLogs(t)

			got, err := GetPluginFileNameToLoad(FileSystemStorage{}, pluginPath)
			require.NoError(t, err)
			assert.Equal(t, pluginPath, got)

			assert.Empty(t, entriesAtOrAbove(hook, logrus.WarnLevel),
				"a plugin that is eventually found must not produce warnings for the candidates that were skipped")
		})
	}
}

func TestGetPluginFileNameToLoad_NotFoundReportsEveryCandidate(t *testing.T) {
	gwVersion := getPrefixedVersion()
	osAndArch := runtime.GOOS + "_" + runtime.GOARCH

	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "myplugin.so")

	hook := captureLogs(t)

	got, err := GetPluginFileNameToLoad(FileSystemStorage{}, pluginPath)
	require.Error(t, err)
	assert.Empty(t, got)

	for _, candidate := range []string{
		filepath.Join(dir, "myplugin_"+gwVersion+"_"+osAndArch+".so"),
		filepath.Join(dir, "myplugin_"+gwVersion[1:]+"_"+osAndArch+".so"),
		pluginPath,
	} {
		assert.Contains(t, err.Error(), candidate, "the error must name every file name that was tried")
	}

	assert.Empty(t, entriesAtOrAbove(hook, logrus.WarnLevel),
		"the loader reports the failure once through the returned error; callers decide how to log it")
}
