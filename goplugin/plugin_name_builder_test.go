package goplugin

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
