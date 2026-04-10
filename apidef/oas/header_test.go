package oas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeaders_Map(t *testing.T) {
	headers := Headers{
		{
			Name:  "k1",
			Value: "v1",
		},
		{
			Name:  "k2",
			Value: "v2",
		},
	}

	expected := map[string]string{
		"k1": "v1",
		"k2": "v2",
	}

	assert.Equal(t, expected, headers.Map())
}

func TestNewHeaders(t *testing.T) {
	in := map[string]string{
		"k2": "v2",
		"k1": "v1",
	}

	expected := Headers{
		{
			Name:  "k1",
			Value: "v1",
		},
		{
			Name:  "k2",
			Value: "v2",
		},
	}

	assert.Equal(t, expected, NewHeaders(in))
}
