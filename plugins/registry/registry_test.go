package registry_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/plugins/registry"
)

func TestPlugin(t *testing.T) {
	p, err := registry.NewPlugin("internal")
	assert.NoError(t, err)

	symbols, err := p.Symbols()
	assert.NoError(t, err)
	assert.Nil(t, symbols, "Expected 0 symbols")

	p.Register("key", func() bool {
		return true
	})

	symbols, err = p.Symbols()
	assert.NoError(t, err)
	assert.Len(t, symbols, 1, "Expected 1 symbol")

	fn, err := p.Lookup("key-404")
	assert.Nil(t, fn)
	assert.Error(t, err)

	fn, err = p.Lookup("key")
	assert.NoError(t, err)

	fv, ok := fn.(func() bool)
	assert.True(t, ok)
	assert.True(t, fv())
}
