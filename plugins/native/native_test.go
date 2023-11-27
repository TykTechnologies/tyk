//go:build plugins_native_test
// +build plugins_native_test

package native_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/plugins/native"
)

func TestPlugin(t *testing.T) {
	p, err := native.NewPlugin("testdata/plugin.so")
	assert.NoError(t, err)

	symbols, err := p.Symbols()
	assert.NoError(t, err)

	for k, v := range symbols {
		fmt.Println("-", k, v)
	}

	_, err = native.NewPlugin("testdata/plugin-404.so")
	assert.Error(t, err)
}
