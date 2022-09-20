package gateway

import (
	"errors"
	"net/http"

	"github.com/TykTechnologies/tyk/internal/flags"
)

// IntrospectionMiddleware verifies and retrieves claims for a token from an introspection endpoint
type IntrospectionMiddleware struct {
	BaseMiddleware

	// Injected flag evaluator
	flags flags.BoolVariant
}

// Assert IntrospectionMiddleware implements TykMiddleware interface
var _ TykMiddleware = &IntrospectionMiddleware{}

func NewIntrospectionMiddleware(base BaseMiddleware, flags flags.BoolVariant) *IntrospectionMiddleware {
	return &IntrospectionMiddleware{
		BaseMiddleware: base,
		flags:          flags,
	}
}

func (*IntrospectionMiddleware) Name() string {
	return "IntrospectionMiddleware"
}

func (mw *IntrospectionMiddleware) EnabledForSpec() bool {
	return mw.flags.Bool(flags.MiddlewareIntrospectionEnabled, nil) && mw.BaseMiddleware.Spec.EnableIntrospection
}

func (mw *IntrospectionMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) {
	return errors.New("not implemented"), 400
}
