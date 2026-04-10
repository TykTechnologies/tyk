package gateway

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/model"
)

type wrapMiddleware struct {
	*BaseMiddleware
	mw model.Middleware
}

var _ TykMiddleware = (*wrapMiddleware)(nil)

// WrapMiddleware returns a new TykMiddleware with the provided base middleware,
// and the smaller model.Middleware interface. It allows to implement model.Middleware,
// and use it as a TykMiddleware.
func WrapMiddleware(base *BaseMiddleware, in model.Middleware) TykMiddleware {
	return &wrapMiddleware{
		BaseMiddleware: base.Copy(),
		mw:             in,
	}
}

func (w *wrapMiddleware) Base() *BaseMiddleware {
	return w.BaseMiddleware
}

func (w *wrapMiddleware) Config() (interface{}, error) {
	return w.BaseMiddleware.Config()
}

func (w *wrapMiddleware) Init() {
	w.mw.Init()
}

func (w *wrapMiddleware) Name() string {
	return w.mw.Name()
}

func (w *wrapMiddleware) Logger() *logrus.Entry {
	return w.mw.Logger()
}

func (w *wrapMiddleware) EnabledForSpec() bool {
	return w.mw.EnabledForSpec()
}

func (w *wrapMiddleware) ProcessRequest(rw http.ResponseWriter, r *http.Request, data interface{}) (error, int) {
	return w.mw.ProcessRequest(rw, r, data)
}

func (w *wrapMiddleware) Unload() {
	w.mw.Unload()
}
