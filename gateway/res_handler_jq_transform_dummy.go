//go:build !jq
// +build !jq

package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/user"
)

type ResponseTransformJQMiddleware struct {
	BaseTykResponseHandler
}

func (h ResponseTransformJQMiddleware) Base() *BaseTykResponseHandler {
	return &h.BaseTykResponseHandler
}

func (ResponseTransformJQMiddleware) Name() string {
	return "ResponseTransformJQMiddleware"
}

func (h *ResponseTransformJQMiddleware) Init(c interface{}, spec *APISpec) error {
	h.Spec = spec

	return nil
}

func (h *ResponseTransformJQMiddleware) HandleError(rw http.ResponseWriter, req *http.Request) {
}

func (h *ResponseTransformJQMiddleware) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	h.logger().Warning("JQ transforms not supported")
	return nil
}
