package logger

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestLogger(t *testing.T) {
	r, err := http.NewRequest("GET", "/", nil)
	assert.Nil(t, err)

	l1 := FromRequest(r)
	l1.Info("First log with data")

	var (
		id  = RequestID(r.Context())
		cid = CorrelationID(r.Context())
	)

	assert.NotEmpty(t, id)
	assert.NotEmpty(t, cid)

	l2 := FromRequest(r)
	l2.Info("Second log with data")

	assert.Equal(t, id, RequestID(r.Context()))
	assert.Equal(t, cid, CorrelationID(r.Context()))
}
