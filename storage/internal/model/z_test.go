package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestZS(t *testing.T) {
	z := ZS{}
	assert.Nil(t, z.Members())
	assert.Nil(t, z.Scores())
}
