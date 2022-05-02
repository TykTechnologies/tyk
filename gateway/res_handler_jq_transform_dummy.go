//go:build !jq
// +build !jq

package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/user"
)

type ResponseTransformJQMiddleware struct {
	Spec *APISpec
	Gw   *Gateway `json:"-"`
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
	log.Warning("JQ transforms not supported")
	return nil
}
