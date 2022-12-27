package internal_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/storage/internal"
)

func TestIsValidDriver(t *testing.T) {
	assert.NoError(t, internal.IsValidDriver("redis"))
	assert.Error(t, internal.IsValidDriver("xxx"))
}
