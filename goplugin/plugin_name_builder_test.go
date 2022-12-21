package goplugin

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
