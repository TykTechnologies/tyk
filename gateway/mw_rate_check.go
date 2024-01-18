package gateway

import (
	"net/http"
)

type RateCheckMW struct {
	*BaseMiddleware
}

func (m *RateCheckMW) Name() string {
	return "RateCheckMW"
}

func (m *RateCheckMW) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	// Let's track r/ps
	GlobalRate.Incr(1)
	return nil, http.StatusOK
}
