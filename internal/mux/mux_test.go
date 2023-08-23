package mux_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/internal/mux"
)

func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Type: %v\n", vars["type"])
}

func newServer(ctx context.Context) {
	r := mux.NewRouter()
	// A route with a route variable:
	r.HandleFunc("/metrics/{type}", MetricsHandler)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	<-ctx.Done()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Println(err)
	}
}

func BenchmarkNewRouter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		r := mux.NewRouter()
		// A route with a route variable:
		r.HandleFunc("/metrics/{type}", MetricsHandler)
	}
}

// endpoints_test.go
func xBenchmarkMetricsHandler(b *testing.B) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go newServer(ctx)

	b.ReportAllocs()

	for i := 0; i < b.N; i++ {

		tt := []struct {
			routeVariable string
			shouldPass    bool
		}{
			{"goroutines", true},
			{"heap", true},
			{"counters", true},
			{"queries", true},
		}

		for _, tc := range tt {
			path := fmt.Sprintf("/metrics/%s", tc.routeVariable)
			req, err := http.NewRequest("GET", path, nil)
			if err != nil {
				b.Fatal(err)
			}

			rr := httptest.NewRecorder()

			// To add the vars to the context,
			// we need to create a router through which we can pass the request.
			router := mux.NewRouter()
			router.HandleFunc("/metrics/{type}", MetricsHandler)
			router.ServeHTTP(rr, req)

			// In this case, our MetricsHandler returns a non-200 response
			// for a route variable it doesn't know about.
			if rr.Code == http.StatusOK && !tc.shouldPass {
				b.Errorf("handler should have failed on routeVariable %s: got %v want %v",
					tc.routeVariable, rr.Code, http.StatusOK)
			}
		}
	}
}
