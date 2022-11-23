//go:build goplugin
// +build goplugin

package goplugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPluginPreload(t *testing.T) {
	t.Parallel()

	name := "_404_.so"
	_, err := pluginOpen(name)
	assert.Error(t, err)

	assert.Error(t, pluginPreload(name, nil))
	assert.Error(t, pluginPreload(name, []byte{}))
	assert.Error(t, pluginPreload(name, []byte("a")))
}
