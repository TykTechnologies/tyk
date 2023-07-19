package httputil

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestUtilities(t *testing.T) {
	w := httptest.NewRecorder()
	EntityTooLarge(w, nil)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Result().StatusCode)

	w = httptest.NewRecorder()
	LengthRequired(w, nil)
	assert.Equal(t, http.StatusLengthRequired, w.Result().StatusCode)

	w = httptest.NewRecorder()
	InternalServerError(w, nil)
	assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
}
