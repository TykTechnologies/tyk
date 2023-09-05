package httputil

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
)

func TestTransportPool(t *testing.T) {
	tp := NewTransportPool()
	assert.NotNil(t, tp)

	t1 := NewTransport(&config.Config{MaxIdleConns: 100}, nil)
	t2 := NewTransport(&config.Config{MaxIdleConns: 200}, nil)

	assert.Equal(t, 100, tp.Put("key", t1).MaxIdleConns)
	assert.Equal(t, 100, tp.Get("key").MaxIdleConns)

	assert.Equal(t, 200, tp.Put("key", t2).MaxIdleConns)
	assert.Equal(t, 200, tp.Get("key").MaxIdleConns)

	tp.CloseIdleConnections()
	tp.Clear()
}
