package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarshalJSON(t *testing.T) {
	value := "foo"
	marshal := MarshalJSON(t)
	out := marshal(value)
	assert.Equal(t, []byte(`"foo"`), out)
}
