package gateway

import (
	"context"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/storage"
)

func TestResponseCacheMiddleware(t *testing.T) {
	res := &ResponseCacheMiddleware{}
	err := res.HandleResponse(nil, nil, nil, nil)

	assert.NoError(t, err)
}

func TestCreateResponseMiddlewareChainSkipsResponseCacheWhenDisabled(t *testing.T) {
	gw := &Gateway{}
	spec := BuildAPI(func(spec *APISpec) {
		spec.APIID = "response-cache-disabled"
		spec.CacheOptions.EnableCache = false
	})[0]

	chain := gw.createResponseMiddlewareChain(spec, nil, testResponseCacheLogger(t))
	if cache := findResponseCacheMiddleware(chain); cache != nil {
		t.Errorf("Gateway.createResponseMiddlewareChain(cache disabled) included %s, want no response cache middleware", cache.Name())
	}
}

func TestCreateResponseMiddlewareChainAddsResponseCacheWhenEnabled(t *testing.T) {
	gw := &Gateway{StorageConnectionHandler: storage.NewConnectionHandler(context.Background())}
	spec := BuildAPI(func(spec *APISpec) {
		spec.APIID = "response-cache-enabled"
		spec.CacheOptions.EnableCache = true
	})[0]

	chain := gw.createResponseMiddlewareChain(spec, nil, testResponseCacheLogger(t))
	cache := findResponseCacheMiddleware(chain)
	if cache == nil {
		t.Fatal("Gateway.createResponseMiddlewareChain(cache enabled) did not include ResponseCacheMiddleware")
	}
	if cache.store == nil {
		t.Error("Gateway.createResponseMiddlewareChain(cache enabled) ResponseCacheMiddleware.store = nil, want cache store")
	}
}

func testResponseCacheLogger(t *testing.T) *logrus.Entry {
	t.Helper()

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return logger.WithField("test", t.Name())
}

func findResponseCacheMiddleware(chain []TykResponseHandler) *ResponseCacheMiddleware {
	for _, handler := range chain {
		if cache, ok := handler.(*ResponseCacheMiddleware); ok {
			return cache
		}
		decorated, ok := handler.(*logDecorator)
		if !ok {
			continue
		}
		if cache, ok := decorated.TykResponseHandler.(*ResponseCacheMiddleware); ok {
			return cache
		}
	}
	return nil
}
