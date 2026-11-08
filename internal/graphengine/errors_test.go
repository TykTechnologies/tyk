package graphengine

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// renderGraphQLError asserts the engine returned a GraphQlError without writing to the
// response itself, then renders it the way the gateway error handler does.
func renderGraphQLError(t *testing.T, err error, statusCode int, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	require.Empty(t, recorder.Body.String(), "engine must not write the error body itself")

	var gqlErr GraphQlError
	require.ErrorAs(t, err, &gqlErr)
	require.NoError(t, gqlErr.WriteToResponse(recorder, statusCode))
	assert.Equal(t, statusCode, recorder.Code)

	return recorder.Body.String()
}
