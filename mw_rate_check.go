package main

import "net/http"

type RateCheckMW struct {
	*TykMiddleware
}

func (m *RateCheckMW) GetName() string {
	return "RateCheckMW"
}

func (m *RateCheckMW) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	// Let's track r/ps
	GlobalRate.Incr(1)
	return nil, 200
}
