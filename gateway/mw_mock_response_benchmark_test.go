package gateway_test

import (
	"fmt"
	mathrand "math/rand"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/ory/dockertest/docker/pkg/ioutils"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/internal/oasbuilder"
)

func BenchmarkRoutersPerformance(b *testing.B) {
	b.Run("classic RxPaths router /resource/{0..n}", func(b *testing.B) {
		addRouterBenchmark(b, "one resource", newClassicRouter(b, 1), newRequestPool(b, 1, routePathGenerator))
		addRouterBenchmark(b, "hundred resources", newClassicRouter(b, 100), newRequestPool(b, 100, routePathGenerator))
		addRouterBenchmark(b, "1k resources", newClassicRouter(b, 1000), newRequestPool(b, 1000, routePathGenerator))
		addRouterBenchmark(b, "one resource", newClassicRouter(b, 10_000), newRequestPool(b, 10_000, routePathGenerator))
	})

	b.Run("kin-openapi gorillamux /resource/{0..n}", func(b *testing.B) {
		addRouterBenchmark(b, "one resource", newMuxRouter(b, 1), newRequestPool(b, 1, routePathGenerator))
		addRouterBenchmark(b, "hundred resources", newMuxRouter(b, 100), newRequestPool(b, 100, routePathGenerator))
		addRouterBenchmark(b, "1k resources", newMuxRouter(b, 1000), newRequestPool(b, 1000, routePathGenerator))
		addRouterBenchmark(b, "1k resources", newMuxRouter(b, 10_000), newRequestPool(b, 10_000, routePathGenerator))
	})
}

func routePathGenerator(i int) string {
	return "/resource/" + strconv.Itoa(i)
}

func addRouterBenchmark(b *testing.B, name string, router routers.Router, reqPool *requestPool) {
	b.Helper()

	b.Run(name, func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := reqPool.next()
			_, _, err := router.FindRoute(req)
			require.NoError(b, err, "expected to find route for: %s", req.URL.Path)
		}
	})
}

func newMuxRouter(tb testing.TB, resources int) routers.Router {
	tb.Helper()

	var spec openapi3.T
	spec.Paths = openapi3.NewPaths()

	for resNum := 0; resNum < resources; resNum++ {
		spec.Paths.Set("/resource/"+strconv.Itoa(resNum), &openapi3.PathItem{
			Get: &openapi3.Operation{},
		})
	}

	router, err := gorillamux.NewRouter(&spec)
	require.NoError(tb, err)
	return router
}

type pathGenerator func(i int) string

type requestPool struct {
	requests []*http.Request
	i        int
}

func newRequestPool(tb testing.TB, maxValue int, gen pathGenerator) *requestPool {
	tb.Helper()

	rnd := mathrand.New(mathrand.NewSource(time.Now().Unix()))
	requests := make([]*http.Request, min(maxValue, 1000))

	for i := 0; i < len(requests); i++ {
		path := gen(rnd.Intn(maxValue))
		req, err := http.NewRequestWithContext(tb.Context(), http.MethodGet, path, nil)
		require.NoError(tb, err)
		requests[i] = req
	}

	return &requestPool{
		requests: requests,
	}
}

func (p *requestPool) next() *http.Request {
	val := p.requests[p.i%len(p.requests)]
	p.i++
	return val
}

func newDummyLogger() *logrus.Entry {
	logger := logrus.New()
	logger.Formatter = &logrus.TextFormatter{}
	logger.Level = logrus.PanicLevel
	logger.Out = &ioutils.NopWriter{}
	return logrus.NewEntry(logger)
}

var _ routers.Router = (*classicRouter)(nil)

type classicRouter struct {
	spec *gateway.APISpec
}

func (c *classicRouter) FindRoute(req *http.Request) (route *routers.Route, pathParams map[string]string, err error) {
	version, _ := c.spec.Version(req)
	versionPaths := c.spec.RxPaths[version.Name]
	_, _ = c.spec.CheckSpecMatchesStatus(req, versionPaths, gateway.OasMock)
	return nil, nil, nil
}

func newClassicRouter(tb testing.TB, resources int) routers.Router {
	tb.Helper()
	cfg, err := config.New()
	require.NoError(tb, err)
	require.NotNil(tb, cfg)
	gw := gateway.NewGateway(*cfg, tb.Context())

	// Create paths for each resource
	builderOpts := []oasbuilder.BuilderOption{
		oasbuilder.WithTestListenPathAndUpstream("/", "http://example.com"),
	}

	// Add a GET endpoint for each resource
	for i := 0; i < resources; i++ {
		resourcePath := "/resource/" + strconv.Itoa(i)
		resourceIndex := i // Capture the value for the closure

		builderOpts = append(builderOpts, oasbuilder.WithGet(resourcePath, func(b *oasbuilder.EndpointBuilder) {
			b.Mock(func(mock *oas.MockResponse) {
				mock.Code = http.StatusOK
				mock.Body = fmt.Sprintf(`{"resource": %d}`, resourceIndex)
				mock.Headers.Add(header.ContentType, "application/json")
			})
		}))
	}

	// Build the OAS definition
	oasDef, err := oasbuilder.Build(builderOpts...)
	require.NoError(tb, err)
	require.NotNil(tb, oasDef)

	// Create API definition from OAS
	var apiDef apidef.APIDefinition
	oasDef.ExtractTo(&apiDef)
	apiDef.IsOAS = true

	// Create merged API
	mergedAPI := &model.MergedAPI{
		APIDefinition: &apiDef,
		OAS:           oasDef,
	}

	// Create API spec
	loader := gateway.APIDefinitionLoader{Gw: gw}
	logger := newDummyLogger()
	spec, err := loader.MakeSpec(mergedAPI, logger)
	require.NoError(tb, err)

	// Verify that RxPaths is populated
	require.NotNil(tb, spec.RxPaths, "RxPaths should not be nil")
	require.NotEmpty(tb, spec.RxPaths[spec.VersionName], "RxPaths should contain paths for the Default version")

	return &classicRouter{spec: spec}
}
