package regression

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/test"
)

func Test_Issue11806_DomainRouting(t *testing.T) {
	testConfig := func(conf *config.Config) {
		conf.EnableCustomDomains = true
	}

	noDomain := LoadAPISpec(t, "testdata/issue-11806-api-no-domain.json")
	withDomain := LoadAPISpec(t, "testdata/issue-11806-api-with-domain.json")

	t.Run("Load listenPath without domain first", func(t *testing.T) {
		ts := gateway.StartTest(testConfig)
		t.Cleanup(ts.Close)

		ts.Gw.LoadAPI(noDomain, withDomain)

		testDomainRouting(t, ts)
	})

	t.Run("Load listenPath with domain first", func(t *testing.T) {
		ts := gateway.StartTest(testConfig)
		t.Cleanup(ts.Close)

		ts.Gw.LoadAPI(withDomain, noDomain)

		testDomainRouting(t, ts)
	})

	t.Run("Test mux router expectations", func(t *testing.T) {
		testSubrouterHost(t)
	})

	t.Run("Test gateway router expectations", func(t *testing.T) {
		testRouteLongestPathFirst(t)
	})
}

func testDomainRouting(tb testing.TB, ts *gateway.Test) {
	tb.Helper()

	ts.Run(tb, []test.TestCase{
		{
			Path:      "/test/",
			Method:    http.MethodGet,
			Code:      http.StatusOK,
			BodyMatch: "fallthrough",
		},
		{
			Path:      "/test/",
			Host:      "example.com",
			Method:    http.MethodGet,
			Code:      http.StatusOK,
			BodyMatch: "example.com",
		},
	}...)
}

// testSubrouterHost verifies directly with gorilla/mux, that the host subrouter
// should be created before adding routes to the main router.
func testSubrouterHost(t *testing.T) {
	t.Helper()

	// Create the main router
	router := mux.NewRouter()
	ctx := context.Background()

	// Create a subrouter with a specific host
	subrouter := router.Host("example.com").Subrouter()
	subrouter.HandleFunc("/test", func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("Subrouter"))
		assert.NoError(t, err)
	})

	// Register a handler for /test on the main router
	router.HandleFunc("/test", func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("Main Router"))
		assert.NoError(t, err)
	})

	// Test a request without the host header
	reqWithoutHost, err := http.NewRequestWithContext(ctx, "GET", "/test", nil)
	assert.NoError(t, err)

	respWithoutHost := httptest.NewRecorder()
	router.ServeHTTP(respWithoutHost, reqWithoutHost)
	if respWithoutHost.Body.String() != "Main Router" {
		t.Errorf("expected 'Main Router', got '%s'", respWithoutHost.Body.String())
	}

	// Test a request with a random host header
	reqWithRandomHost, err := http.NewRequestWithContext(ctx, "GET", "/test", nil)
	assert.NoError(t, err)

	reqWithRandomHost.Host = "random.mydomain.com"
	respWithRandomHost := httptest.NewRecorder()
	router.ServeHTTP(respWithRandomHost, reqWithRandomHost)
	if respWithRandomHost.Body.String() != "Main Router" {
		t.Errorf("expected 'Main Router', got '%s'", respWithRandomHost.Body.String())
	}

	// Test a request with the specific host header
	reqWithSpecificHost, err := http.NewRequestWithContext(ctx, "GET", "/test", nil)
	assert.NoError(t, err)

	reqWithSpecificHost.Host = "example.com"
	respWithSpecificHost := httptest.NewRecorder()
	router.ServeHTTP(respWithSpecificHost, reqWithSpecificHost)
	if respWithSpecificHost.Body.String() != "Subrouter" {
		t.Errorf("expected 'Subrouter', got '%s'", respWithSpecificHost.Body.String())
	}
}

func testRouteLongestPathFirst(t *testing.T) {
	t.Helper()

	ts := gateway.StartTest(func(globalConf *config.Config) {
		globalConf.EnableCustomDomains = true
	})
	t.Cleanup(ts.Close)

	type hostAndPath struct {
		host, path string
	}

	inputs := map[hostAndPath]bool{}
	hosts := []string{"host1.local", "host2.local", "host3.local"}
	paths := []string{"a", "ab", "a/b/c", "ab/c", "abc", "a/b/c"}

	for _, host := range hosts {
		for _, path := range paths {
			inputs[hostAndPath{host, path}] = true
		}
	}

	var apis []*gateway.APISpec

	for hp := range inputs {
		apis = append(apis, gateway.BuildAPI(func(spec *gateway.APISpec) {
			spec.APIID = uuid.New()

			spec.Domain = hp.host
			spec.Proxy.ListenPath = "/" + hp.path
		})[0])
	}

	ts.Gw.LoadAPI(apis...)

	var testCases []test.TestCase

	for hp := range inputs {
		testCases = append(testCases, test.TestCase{
			Client:    test.NewClientLocal(),
			Path:      "/" + hp.path,
			Domain:    hp.host,
			Code:      200,
			BodyMatch: `"Url":"/` + hp.path + `"`,
		})
	}

	_, _ = ts.Run(t, testCases...)
}
