package gateway

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGoPluginFromTykVersion(t *testing.T) {
	t.Parallel()

	m := GoPluginMiddleware{
		BaseMiddleware: BaseMiddleware{},
		Path:           "",
		SymbolName:     "test-symbol",
	}

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

	for _, version := range []string{expectVersion, expectVersion + "-rc16"} {
		testcases = append(testcases, []testCase{
			{version, "plugin.so", fmt.Sprintf("./plugin_%v_%v_%v.so", expectVersion, goos, goarch)},
			{version, "/some/path/plugin.so", fmt.Sprintf("/some/path/plugin_%v_%v_%v.so", expectVersion, goos, goarch)},
			{version, "/some/path/plugin", fmt.Sprintf("/some/path/plugin_%v_%v_%v.so", expectVersion, goos, goarch)},
			{version, "./plugin.so", fmt.Sprintf("./plugin_%v_%v_%v.so", expectVersion, goos, goarch)},
		}...)
	}

	for idx, tc := range testcases {
		t.Run(fmt.Sprintf("Test case: %d", idx), func(t *testing.T) {
			t.Parallel()

			m.Path = tc.userDefinedName
			newPluginPath := m.goPluginFromTykVersion(tc.version)
			assert.Equal(t, tc.inferredName, newPluginPath)
		})
	}
}
