package gateway_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/test"
)

func TestMascotShowsUpOnceOnly(t *testing.T) {
	ts := gateway.StartTest()
	defer ts.Close()

RequestLoop:
	for i := 0; i < 7; i++ {
		resp, _ := ts.Run(t, test.TestCase{ //nolint:errcheck // Errors are checked internally
			Method: http.MethodGet,
			Path:   "/" + ts.GlobalConfig.HealthCheckEndpointName,
			Code:   http.StatusOK,
		})

		if i == 0 {
			for key := range resp.Header {
				if strings.Contains(strings.ToLower(key), "mascot") {
					continue RequestLoop
				}
			}

			t.Fatalf("mascot headers should appear in first health check call only")
		}

		for key := range resp.Header {
			if strings.Contains(strings.ToLower(key), "mascot") {
				t.Fatalf("mascot header '%s' should not appear in health check after first call", key)
			}
		}
	}
}
