package gateway

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGoPluginFromTykVersion(t *testing.T) {
	m := GoPluginMiddleware{
		BaseMiddleware: BaseMiddleware{},
		Path:           "",
		SymbolName:     "test-symbol",
	}

	type testCase struct {
		userDefinedName, inferredName string
	}
	os := runtime.GOOS
	arch := runtime.GOARCH

	matrix := []testCase{
		{"plugin.so", fmt.Sprintf("./plugin_%v_%v_%v.so", VERSION, os, arch)},
		{"/some/path/plugin.so", fmt.Sprintf("/some/path/plugin_%v_%v_%v.so", VERSION, os, arch)},
		{"/some/path/plugin", fmt.Sprintf("/some/path/plugin_%v_%v_%v.so", VERSION, os, arch)},
		{"./plugin.so", fmt.Sprintf("./plugin_%v_%v_%v.so", VERSION, os, arch)},
		{"", ""},
	}

	for _, v := range matrix {
		m.Path = v.userDefinedName
		newPluginPath := m.goPluginFromTykVersion()
		assert.Equal(t, v.inferredName, newPluginPath)
	}
}
