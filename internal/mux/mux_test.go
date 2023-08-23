package mux_test

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/internal/mux"
)

func BenchmarkNewRouter(b *testing.B) {
	handler := http.NotFoundHandler()

	for i := 0; i < b.N; i++ {
		r := mux.NewRouter()
		// A route with a route variable:
		r.Handle("/metrics/{type}", handler)
		r.Queries("orgID", "{orgID:[0-9]*?}")
		r.Host("{subdomain}.domain.com")
	}
}

func TestNewRouter(t *testing.T) {
	handler := http.NotFoundHandler()

	r := mux.NewRouter()
	// A route with a route variable:
	r.Handle("/metrics/{type}", handler)
	r.Queries("orgID", "{orgID:[0-9]*?}")
	r.Host("{subdomain}.domain.com")
}
