package health

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type HealthAggregationsResponse struct {
	InstanceId           string                 `json:"instance_id"`
	IntervalDuration     time.Duration          `json:"interval_duration"`
	IntervalAggregations []*IntervalAggregation `json:"aggregations"`
}

func (s *JsonPollingSink) StartServer(addr string) {
	go http.ListenAndServe(addr, s)
}

func (s *JsonPollingSink) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.URL.Path == "/health" {
		metrics := s.GetMetrics()
		response := &HealthAggregationsResponse{
			InstanceId:           Identifier,
			IntervalDuration:     s.intervalDuration,
			IntervalAggregations: metrics,
		}
		jsonData, err := json.MarshalIndent(response, "", "\t")
		if err != nil {
			renderError(rw, err)
			return
		}
		fmt.Fprintf(rw, string(jsonData))
	} else {
		renderNotFound(rw)
	}
}

func renderNotFound(rw http.ResponseWriter) {
	rw.WriteHeader(404)
	fmt.Fprintf(rw, `{"error": "not_found"}`)
}

func renderError(rw http.ResponseWriter, err error) {
	rw.WriteHeader(500)
	fmt.Fprintf(rw, `{"error": "%s"}`, err.Error())
}
