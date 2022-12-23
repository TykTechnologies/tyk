package goplugin

import (
	"fmt"
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
	gwVersion := "v4.1.0"
	gwVersionWithoutPrefix := "4.1.0"
	OSandArch := runtime.GOOS + "_" + runtime.GOARCH

	testCases := []struct {
		name             string
		pluginName       string
		files            []string
		expectedFileName string
		version          string
	}{
		{
			name:             "base name file exist",
			pluginName:       "myplugin.so",
			files:            []string{"myplugin.so", "myplugin", "anything-else"},
			expectedFileName: "myplugin.so",
			version:          gwVersion,
		},
		{
			name:             "exist plugin file that follows new formatting",
			pluginName:       "myplugin.so",
			files:            []string{"myplugin_v4.1.0_" + OSandArch + ".so", "myplugin_v4.1.0_linux_amd64.so", "myplugin", "anything-else"},
			expectedFileName: "./myplugin_v4.1.0_" + OSandArch + ".so",
			version:          gwVersion,
		},
		{
			// in some point we had an issue where name loaded didn't contain prefix v. So we keep it for backward compatibility
			name:             "exist plugin file that follows new formatting but gw version without prefix v",
			pluginName:       "myplugin.so",
			files:            []string{"myplugin_4.1.0_" + OSandArch + ".so", "myplugin", "anything-else", "myplugin.so"},
			expectedFileName: "./myplugin_4.1.0_" + OSandArch + ".so",
			version:          gwVersionWithoutPrefix,
		},
		{
			name:             "append prefix to gateway version",
			pluginName:       "myplugin.so",
			files:            []string{"myplugin_v4.1.0_" + OSandArch + ".so"},
			expectedFileName: "./myplugin_v4.1.0_" + OSandArch + ".so",
			version:          gwVersionWithoutPrefix,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			pluginStorage = MockStorage{
				files: testCase.files,
			}

			filenameToLoad, _ := GetPluginFileNameToLoad(testCase.pluginName, testCase.version)
			assert.Equal(t, testCase.expectedFileName, filenameToLoad)
		})
	}

}

func TestGetPrefixedVersion(t *testing.T) {
	version := getPrefixedVersion("v4.1.0")
	expectedVersion := "v4.1.0"
	assert.Equal(t, expectedVersion, version)

	testCases := []struct {
		name, version, expectedVersion string
	}{
		{
			name:            "version with the prefix V",
			version:         "v4.1.0",
			expectedVersion: "v4.1.0",
		},
		{
			name:            "version without the prefix v",
			version:         "4.1.0",
			expectedVersion: "v4.1.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			version := getPrefixedVersion(tc.version)
			assert.Equal(t, tc.expectedVersion, version)
		})
	}
}

func TestGetGoPluginNameFromTykVersion(t *testing.T) {

	type testCase struct {
		version, userDefinedName, inferredName string
	}
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	testcases := []testCase{
		{"", "", ""},
	}

	// Go middleware compiler only reads the pre-injected
	// VERSION value from version.go, expecting to search
	// plugin with clean version in filename (no -rc16).
	expectVersion := "v4.1.0"

	versions := []struct {
		version, expectedVersion string
	}{
		{
			version:         expectVersion,
			expectedVersion: expectVersion,
		},
		{
			version:         expectVersion + "-rc16",
			expectedVersion: expectVersion,
		},
		{
			version:         "4.1.0",
			expectedVersion: "4.1.0",
		},
	}
	for _, version := range versions {
		testcases = append(testcases, []testCase{
			{version.version, "plugin.so", fmt.Sprintf("./plugin_%v_%v_%v.so", version.expectedVersion, goos, goarch)},
			{version.version, "/some/path/plugin.so", fmt.Sprintf("/some/path/plugin_%v_%v_%v.so", version.expectedVersion, goos, goarch)},
			{version.version, "/some/path/plugin", fmt.Sprintf("/some/path/plugin_%v_%v_%v.so", version.expectedVersion, goos, goarch)},
			{version.version, "./plugin.so", fmt.Sprintf("./plugin_%v_%v_%v.so", version.expectedVersion, goos, goarch)},
		}...)
	}

	for _, tc := range testcases {
		t.Run(fmt.Sprintf("GW version:%v-Plugin Name:%v", tc.version, tc.inferredName), func(t *testing.T) {

			newPluginPath := getPluginNameFromTykVersion(tc.version, tc.userDefinedName)
			assert.Equal(t, tc.inferredName, newPluginPath)
		})
	}
}
