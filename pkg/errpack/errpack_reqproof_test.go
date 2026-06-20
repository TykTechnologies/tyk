package errpack_test

import (
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/pkg/errpack"
)

// Verifies: SYS-REQ-082, SW-REQ-066
// SW-REQ-066:nominal:nominal
// SW-REQ-066:boundary:nominal
// SW-REQ-066:error_handling:nominal
// SW-REQ-066:error_handling:negative
// SW-REQ-066:determinism:nominal
func TestErrpackPreservesDiagnosticErrorMetadata(t *testing.T) {
	t.Run("constructors preserve message and type metadata", func(t *testing.T) {
		cases := []struct {
			name string
			err  errpack.Error
			typ  errpack.Type
			msg  string
		}{
			{name: "default unknown", err: errpack.New("raw"), typ: errpack.TypeUnknown, msg: "raw"},
			{name: "domain", err: errpack.Domain("bad input"), typ: errpack.TypeDomain, msg: "bad input"},
			{name: "infra", err: errpack.Infra("redis down"), typ: errpack.TypeInfrastructure, msg: "redis down"},
			{name: "application", err: errpack.Application("misconfigured"), typ: errpack.TypeApp, msg: "misconfigured"},
			{name: "not found", err: errpack.NotFoundWithId("policy-1"), typ: errpack.TypeNotFound, msg: `entry not found: "policy-1"`},
			{name: "broken invariant", err: errpack.New("unreachable", errpack.WithType(errpack.BrokenInvariant)), typ: errpack.BrokenInvariant, msg: "unreachable"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				require.Equal(t, tc.msg, tc.err.Error())
				require.True(t, tc.err.TypeOf(tc.typ))
				require.False(t, tc.err.TypeOf(errpack.TypeDomain) && tc.typ != errpack.TypeDomain)
			})
		}
	})

	t.Run("formatted domain errors keep domain type and predecessor chain", func(t *testing.T) {
		err := errpack.Domainf("field %s: %s", "name", "invalid")

		require.Equal(t, "field name: invalid", err.Error())
		require.True(t, err.TypeOf(errpack.TypeDomain))
		require.NotNil(t, errors.Unwrap(err))
		require.Equal(t, "field name: invalid", errors.Unwrap(err).Error())
	})

	t.Run("wrapping and chaining preserve predecessor errors", func(t *testing.T) {
		raw := errors.New("source")
		wrapped := errpack.Wrap(raw, errpack.WithType(errpack.TypeInfrastructure), errpack.WithLogLevel(logrus.WarnLevel))

		require.ErrorIs(t, wrapped, raw)
		require.Equal(t, "source", wrapped.Error())
		require.Equal(t, logrus.WarnLevel, errpack.LogLevel(wrapped, logrus.DebugLevel))

		chained := errpack.Domain("outer").Chain(raw)
		require.ErrorIs(t, chained, raw)
		require.True(t, errors.Is(chained, errpack.Domain("outer").Chain(raw)))
		require.False(t, errors.Is(chained, errpack.Domain("outer")))
		require.False(t, errors.Is(chained, errpack.Domain("different")))
	})

	t.Run("log level fallback is deterministic for unwrapped errors and wrapped errors", func(t *testing.T) {
		raw := errors.New("raw")
		wrapped := errpack.Wrap(raw, errpack.WithLogLevel(logrus.ErrorLevel))

		for i := 0; i < 3; i++ {
			require.Equal(t, logrus.InfoLevel, errpack.LogLevel(nil, logrus.InfoLevel))
			require.Equal(t, logrus.DebugLevel, errpack.LogLevel(raw, logrus.DebugLevel))
			require.Equal(t, logrus.ErrorLevel, errpack.LogLevel(wrapped, logrus.TraceLevel))
		}
	})
}
