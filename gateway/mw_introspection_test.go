package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/flags"
)

type testBoolVariant struct {
	BoolVariant bool
}

func (f testBoolVariant) Bool(flags.FlagKey, flags.User) bool {
	return f.BoolVariant
}

func TestIntrospectionMiddlewareEnabled(t *testing.T) {
	t.Parallel()

	flagEnabled := testBoolVariant{true}
	flagDisabled := testBoolVariant{false}

	specEnabled := BuildAPI(func(spec *APISpec) {
		spec.EnableIntrospection = true
	})[0]
	specDisabled := BuildAPI(func(spec *APISpec) {
		spec.EnableIntrospection = false
	})[0]

	testcases := []struct {
		title    string
		base     BaseMiddleware
		flags    flags.BoolVariant
		expected bool
	}{
		{
			title: "disabled spec, disabled flag",
			base: BaseMiddleware{
				Spec: specDisabled,
			},
			flags:    flagDisabled,
			expected: false,
		},
		{
			title: "enabled spec, disabled flag",
			base: BaseMiddleware{
				Spec: specEnabled,
			},
			flags:    flagDisabled,
			expected: false,
		},
		{
			title: "disabled spec, enabled flag",
			base: BaseMiddleware{
				Spec: specDisabled,
			},
			flags:    flagEnabled,
			expected: false,
		},
		{
			title: "enabled spec, enabled flag",
			base: BaseMiddleware{
				Spec: specEnabled,
			},
			flags:    flagEnabled,
			expected: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()

			mw := NewIntrospectionMiddleware(tc.base, tc.flags)
			assert.Equal(t, tc.expected, mw.EnabledForSpec())
		})
	}
}
