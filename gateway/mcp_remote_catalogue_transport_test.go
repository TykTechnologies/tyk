package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/internal/crypto"
)

// catalogueProbeOverrides overrides delete_repo and archived_tool. Only
// delete_repo is in the probe upstreams, so a check that lists the catalogue
// logs a missing-source warning for archived_tool.
func catalogueProbeOverrides() []oas.TykMCPServerPrimitive {
	return []oas.TykMCPServerPrimitive{
		annotationOverride("delete_repo", oas.DerivedToolAnnotations{DestructiveHint: boolPtr(true)}),
		annotationOverride("archived_tool", oas.DerivedToolAnnotations{ReadOnlyHint: boolPtr(true)}),
	}
}

func assertCatalogueListed(t *testing.T, logs *remoteMCPLogRecorder) {
	t.Helper()
	assert.Nil(t, logs.find(logrus.WarnLevel, "applying them unchecked"), "the catalogue must be listed")
	assert.NotNil(t, logs.find(logrus.WarnLevel, "not in the upstream tool list", "source_tool=archived_tool"), "the check must compare the catalogue")
}

// recordedHeaders keeps the headers of the first request a test upstream
// received, and counts requests.
type recordedHeaders struct {
	mu     sync.Mutex
	header http.Header
	hits   int
}

func (r *recordedHeaders) record(h http.Header) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.header == nil {
		r.header = h.Clone()
	}
	r.hits++
}

func (r *recordedHeaders) get(name string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.header.Get(name)
}

func (r *recordedHeaders) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits
}

func newHeaderRecordingRemoteMCPServer(t *testing.T, tools ...string) (*httptest.Server, *recordedHeaders) {
	t.Helper()
	fake, _ := newFakeRemoteMCPServer(t, tools...)
	seen := &recordedHeaders{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.record(r.Header)
		fake.ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Close)
	return upstream, seen
}

func TestRemoteMCPCatalogue_UpstreamTransport(t *testing.T) {
	t.Run("static global request headers are sent; placeholders that need a request are not", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-catalogue-headers"
		logs := recordRemoteMCPLogs(t, apiID)
		upstream, seen := newHeaderRecordingRemoteMCPServer(t, `{"name":"delete_repo"}`)

		spec := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, catalogueProbeOverrides(), func(spec *APISpec) {
			version := spec.VersionData.Versions["Default"]
			version.GlobalHeaders = map[string]string{
				"X-Upstream-Tenant": "acme",
				"X-Client-Address":  "$tyk_context.remote_addr",
				"X-Key-Owner":       "$tyk_meta.owner",
			}
			spec.VersionData.Versions["Default"] = version
			spec.OAS.Fill(*spec.APIDefinition)
		})
		waitForRemoteMCPToolViewCheck(t, spec)

		assertCatalogueListed(t, logs)
		assert.Equal(t, "acme", seen.get("X-Upstream-Tenant"))
		assert.Empty(t, seen.get("X-Client-Address"), "a context placeholder cannot be resolved without a request")
		assert.Empty(t, seen.get("X-Key-Owner"), "a session placeholder cannot be resolved without a request")
	})

	t.Run("upstream mTLS certificate is presented", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-catalogue-mtls"
		logs := recordRemoteMCPLogs(t, apiID)

		_, _, combinedClientPEM, clientCert := crypto.GenCertificate(&x509.Certificate{}, false)
		leaf, err := x509.ParseCertificate(clientCert.Certificate[0])
		require.NoError(t, err)
		clientCert.Leaf = leaf
		clientCertID, err := ts.Gw.CertificateManager.Add(combinedClientPEM, "")
		require.NoError(t, err)
		t.Cleanup(func() { ts.Gw.CertificateManager.Delete(clientCertID, "") })

		fake, _ := newFakeRemoteMCPServer(t, `{"name":"delete_repo"}`)
		pool := x509.NewCertPool()
		pool.AddCert(clientCert.Leaf)
		upstream := httptest.NewUnstartedServer(fake)
		upstream.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
		upstream.StartTLS()
		t.Cleanup(upstream.Close)

		spec := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, catalogueProbeOverrides(), func(spec *APISpec) {
			spec.UpstreamCertificates = map[string]string{"*": clientCertID}
			spec.Proxy.Transport.SSLInsecureSkipVerify = true
			spec.OAS.Fill(*spec.APIDefinition)
		})
		waitForRemoteMCPToolViewCheck(t, spec)

		assertCatalogueListed(t, logs)
	})

	t.Run("SSLInsecureSkipVerify decides whether a self-signed upstream is trusted", func(t *testing.T) {
		for _, skip := range []bool{true, false} {
			ts := StartTest(nil)
			t.Cleanup(ts.Close)
			apiID := "remote-mcp-catalogue-skip-verify"
			if !skip {
				apiID += "-off"
			}
			logs := recordRemoteMCPLogs(t, apiID)
			fake, _ := newFakeRemoteMCPServer(t, `{"name":"delete_repo"}`)
			upstream := httptest.NewTLSServer(fake)
			t.Cleanup(upstream.Close)

			spec := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, catalogueProbeOverrides(), func(spec *APISpec) {
				spec.Proxy.Transport.SSLInsecureSkipVerify = skip
				spec.OAS.Fill(*spec.APIDefinition)
			})
			waitForRemoteMCPToolViewCheck(t, spec)

			if skip {
				assertCatalogueListed(t, logs)
			} else {
				assert.NotNil(t, logs.find(logrus.WarnLevel, "applying them unchecked"), "an untrusted certificate fails the check")
			}
		}
	})

	t.Run("an h2c upstream is listed over HTTP/2 cleartext", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-catalogue-h2c"
		logs := recordRemoteMCPLogs(t, apiID)
		fake, _ := newFakeRemoteMCPServer(t, `{"name":"delete_repo"}`)
		var http2Requests atomic.Int32
		upstream := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor == 2 {
				http2Requests.Add(1)
			}
			fake.ServeHTTP(w, r)
		}), &http2.Server{}))
		t.Cleanup(upstream.Close)

		spec := loadRemoteMCPProxy(t, ts, apiID, "h2c://"+upstream.Listener.Addr().String(), catalogueProbeOverrides())
		waitForRemoteMCPToolViewCheck(t, spec)

		assertCatalogueListed(t, logs)
		assert.Positive(t, http2Requests.Load(), "the check must speak HTTP/2 cleartext, as the proxy does")
	})

	t.Run("the API's proxy URL is used", func(t *testing.T) {
		ts := StartTest(nil)
		t.Cleanup(ts.Close)
		const apiID = "remote-mcp-catalogue-proxy-url"
		logs := recordRemoteMCPLogs(t, apiID)
		_, upstream := newFakeRemoteMCPServer(t, `{"name":"delete_repo"}`)

		var proxied atomic.Int32
		forwardProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxied.Add(1)
			target, err := url.Parse(r.URL.Scheme + "://" + r.URL.Host)
			if err != nil || r.URL.Host == "" {
				http.Error(w, "not a proxy request", http.StatusBadRequest)
				return
			}
			httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
		}))
		t.Cleanup(forwardProxy.Close)

		spec := loadRemoteMCPProxy(t, ts, apiID, upstream.URL, catalogueProbeOverrides(), func(spec *APISpec) {
			spec.Proxy.Transport.ProxyURL = forwardProxy.URL
			spec.OAS.Fill(*spec.APIDefinition)
		})
		waitForRemoteMCPToolViewCheck(t, spec)

		assertCatalogueListed(t, logs)
		assert.Positive(t, proxied.Load(), "the catalogue requests must go through the configured proxy")
	})
}
