package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/internal/reflect"
	"github.com/stretchr/testify/assert"
)

func TestConfig_replaceKeyValue(t *testing.T) {
	conf, err := NewDefaultWithEnv()
	assert.NoError(t, err)

	// sets up mock data by replacing the default string values
	// with a value that is prefixed with `vault://`.
	var index int
	reflect.TraverseAndReplace(conf, func(string) (string, bool) {
		index++
		return "vault://key/" + fmt.Sprint(index), true
	})

	// list all values prefixed with `vault://`
	values := reflect.TraverseAndFind(conf, func(in string) bool {
		return strings.HasPrefix(in, "vault://")
	})

	// assert the found value count matches
	assert.Len(t, values, index)
	t.Logf("Found/replaced %d values", len(values))
}
