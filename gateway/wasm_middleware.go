package gateway

import (
	"net/http"

	"github.com/TykTechnologies/tyk/wasm/v1/handler"
)

var _ TykMiddleware = (*WasmMiddleware)(nil)

type WasmMiddleware struct {
	BaseMiddleware
	H *handler.H
}

func (WasmMiddleware) Name() string {
	return "WasmMiddleware"
}

func (m *WasmMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) {
	return m.H.ProcessRequest(w, r, conf)
}
