package gateway_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/test"
)

func TestMascotShowsUpOnceOnly(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	for i := 0; i < 7; i++ {
		resp, _ := ts.Run(t, test.TestCase{
			Method: http.MethodGet,
			Path:   "/" + ts.Gw.GetConfig().HealthCheckEndpointName,
			Code:   http.StatusOK,
		})
		defer resp.Body.Close()

		if i == 0 {
			// In any given test run, this might not be the very first request to the test gateway's health check endpoint.
			// Asserting here leads to flakiness.
			continue
		}

		for key := range resp.Header {
			if strings.Contains(strings.ToLower(key), "mascot") {
				t.Fatalf("mascot header '%s' should not appear in health check after first call", key)
			}
		}
	}
}
