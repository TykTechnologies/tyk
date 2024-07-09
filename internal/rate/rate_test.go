package rate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrefix(t *testing.T) {
	t.Parallel()

	key := Prefix("a", "b", "", "c")
	assert.Equal(t, "a-b-c", key)
}
