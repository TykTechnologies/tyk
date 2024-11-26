package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/user"
)

type wrapResponseHandler struct {
	*BaseTykResponseHandler
	rh model.ResponseMiddleware
}

var _ TykResponseHandler = &wrapResponseHandler{}

func WrapResponseHandler(base *BaseTykResponseHandler, in model.ResponseMiddleware) TykResponseHandler {
	return &wrapResponseHandler{
		BaseTykResponseHandler: base,
		rh:                     in,
	}
}

func (w *wrapResponseHandler) Base() *BaseTykResponseHandler {
	return w.BaseTykResponseHandler
}

func (w *wrapResponseHandler) Init(i interface{}, spec *APISpec) error {
	return w.rh.Init(i, spec.APIDefinition)
}

func (w *wrapResponseHandler) Name() string {
	return w.rh.Name()
}

func (w *wrapResponseHandler) Enabled() bool {
	return w.rh.Enabled()
}

func (w *wrapResponseHandler) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	return w.rh.HandleResponse(rw, res, req, ses)
}

func (w *wrapResponseHandler) HandleError(rw http.ResponseWriter, req *http.Request) {
	w.rh.HandleError(rw, req)
}
