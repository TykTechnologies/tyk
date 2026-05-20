package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// T8
func TestAutoMaxProcsEnabled(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		{"0", false},
		{"false", false},
		{"no", false},
		{"off", false},
		{"disabled", false},
		{"FALSE", false},
		{"  0  ", false},
		{"", true},
		{"1", true},
		{"true", true},
		{"anything", true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("TYK_GW_AUTOMAXPROCS", tc.env)
			assert.Equal(t, tc.want, autoMaxProcsEnabled())
		})
	}
}
