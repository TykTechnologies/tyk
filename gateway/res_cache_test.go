package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResponseCacheMiddleware(t *testing.T) {
	res := &ResponseCacheMiddleware{}
	err := res.HandleResponse(nil, nil, nil, nil)

	assert.NoError(t, err)
}
