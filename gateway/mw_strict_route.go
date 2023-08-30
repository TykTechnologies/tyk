package gateway

import (
	"net/http"
	"strings"
)

type StrictRoutesMW struct {
	BaseMiddleware
}

func (s *StrictRoutesMW) Name() string {
	return "StrictRoutesMW"
}

func (s *StrictRoutesMW) EnabledForSpec() bool {
	return s.Gw.GetConfig().HttpServerOptions.EnableStrictRoutes
}

func (s *StrictRoutesMW) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if !s.Gw.GetConfig().HttpServerOptions.EnableStrictRoutes {
		return nil, http.StatusOK
	}

	listenPath := s.Spec.Proxy.ListenPath

	// keep paths with params as-is
	if strings.Contains(listenPath, "{") && strings.Contains(listenPath, "}") {
		return nil, http.StatusOK
	}

	if r.URL.Path == listenPath || strings.HasPrefix(r.URL.Path, listenPath+"/") {
		return nil, http.StatusOK
	}

	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(http.StatusText(http.StatusNotFound)))
	return nil, mwStatusRespond
}
