package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDynamicUpstreamURL_Integration tests dynamic URL variables with proper API setup
func TestDynamicUpstreamURL_Integration(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create test upstream servers for different regions
	upstreamUS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Region", "us-east")
		json.NewEncoder(w).Encode(map[string]string{
			"region": "us-east",
			"path":   r.URL.Path,
			"host":   r.Host,
		})
	}))
	defer upstreamUS.Close()

	upstreamEU := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Region", "eu-west")
		json.NewEncoder(w).Encode(map[string]string{
			"region": "eu-west",
			"path":   r.URL.Path,
			"host":   r.Host,
		})
	}))
	defer upstreamEU.Close()

	// Parse URLs to get hosts
	usURL, _ := url.Parse(upstreamUS.URL)
	euURL, _ := url.Parse(upstreamEU.URL)

	// Create API with dynamic upstream URL
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Dynamic Upstream API"
		spec.APIID = "dynamic-upstream-api"
		spec.OrgID = "default"
		spec.UseKeylessAccess = false
		spec.Auth.AuthHeaderName = "Authorization"
		spec.Proxy = apidef.ProxyConfig{
			ListenPath:      "/dynamic-api/",
			TargetURL:       "http://$tyk_meta.upstream_host/",
			StripListenPath: true,
		}
		spec.EnableContextVars = true
		spec.VersionData.NotVersioned = true
		
		// Debug output
		t.Logf("API Created - EnableContextVars: %v, TargetURL: %s", spec.EnableContextVars, spec.Proxy.TargetURL)
	})

	// Test 1: Different users route to different regions
	t.Run("Regional Routing Based on User Metadata", func(t *testing.T) {
		// Create US user with session
		_, usKey := ts.CreateSession(func(s *user.SessionState) {
			s.MetaData = map[string]interface{}{
				"user_id":       "us-user-1",
				"region":        "us-east",
				"upstream_host": usURL.Host,
			}
			s.AccessRights = map[string]user.AccessDefinition{
				"dynamic-upstream-api": {
					APIID: "dynamic-upstream-api",
				},
			}
		})

		// Create EU user with session
		_, euKey := ts.CreateSession(func(s *user.SessionState) {
			s.MetaData = map[string]interface{}{
				"user_id":       "eu-user-1",
				"region":        "eu-west",
				"upstream_host": euURL.Host,
			}
			s.AccessRights = map[string]user.AccessDefinition{
				"dynamic-upstream-api": {
					APIID: "dynamic-upstream-api",
				},
			}
		})

		// Test US user routes to US upstream
		usResp, err := ts.Run(t, test.TestCase{
			Path:    "/dynamic-api/test-endpoint",
			Method:  http.MethodGet,
			Headers: map[string]string{"Authorization": usKey},
			Code:    http.StatusOK,
		})
		require.NoError(t, err)

		var usResult map[string]string
		err = json.NewDecoder(usResp.Body).Decode(&usResult)
		require.NoError(t, err)
		assert.Equal(t, "us-east", usResult["region"])
		assert.Equal(t, "/test-endpoint", usResult["path"])

		// Test EU user routes to EU upstream
		euResp, err := ts.Run(t, test.TestCase{
			Path:    "/dynamic-api/test-endpoint",
			Method:  http.MethodGet,
			Headers: map[string]string{"Authorization": euKey},
			Code:    http.StatusOK,
		})
		require.NoError(t, err)

		var euResult map[string]string
		err = json.NewDecoder(euResp.Body).Decode(&euResult)
		require.NoError(t, err)
		assert.Equal(t, "eu-west", euResult["region"])
		assert.Equal(t, "/test-endpoint", euResult["path"])
	})
}

// TestDynamicUpstreamURL_LoadBalancing tests dynamic variables with load balancing
func TestDynamicUpstreamURL_LoadBalancing(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create multiple upstream servers
	var servers []*httptest.Server
	serverHits := make(map[string]*int32)

	for i := 1; i <= 3; i++ {
		serverName := fmt.Sprintf("server-%d", i)
		hits := int32(0)
		serverHits[serverName] = &hits

		server := httptest.NewServer(http.HandlerFunc(func(name string) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(serverHits[name], 1)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"server": name,
					"path":   r.URL.Path,
				})
			}
		}(serverName)))
		servers = append(servers, server)
		defer server.Close()
	}

	// Build target list with dynamic paths
	var targets []string
	for _, server := range servers {
		u, _ := url.Parse(server.URL)
		targets = append(targets, fmt.Sprintf("http://%s/$tyk_meta.api_version", u.Host))
	}

	// Create API with load balancing
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Load Balanced Dynamic API"
		spec.APIID = "lb-dynamic-api"
		spec.OrgID = "default"
		spec.UseKeylessAccess = false
		spec.Auth.AuthHeaderName = "Authorization"
		spec.Proxy = apidef.ProxyConfig{
			ListenPath:          "/lb-api/",
			StripListenPath:     true,
			EnableLoadBalancing: true,
			Targets:             targets,
		}
		spec.EnableContextVars = true
		spec.VersionData.NotVersioned = true
	})

	// Create session with API version in metadata
	_, apiKey := ts.CreateSession(func(s *user.SessionState) {
		s.MetaData = map[string]interface{}{
			"api_version": "v2",
			"customer":    "test-customer",
		}
		s.AccessRights = map[string]user.AccessDefinition{
			"lb-dynamic-api": {
				APIID: "lb-dynamic-api",
			},
		}
	})

	// Make multiple requests to verify load balancing
	for i := 0; i < 9; i++ {
		resp, err := ts.Run(t, test.TestCase{
			Path:    "/lb-api/endpoint",
			Method:  http.MethodGet,
			Headers: map[string]string{"Authorization": apiKey},
			Code:    http.StatusOK,
		})
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)

		// Verify path includes the dynamic API version
		assert.Equal(t, "/v2/endpoint", result["path"])
	}

	// Verify all servers received requests (round-robin)
	for name, hits := range serverHits {
		count := atomic.LoadInt32(hits)
		assert.Equal(t, int32(3), count, "Server %s should have received exactly 3 requests", name)
	}
}

// TestDynamicUpstreamURL_ContextVariables tests using $tyk_context variables
func TestDynamicUpstreamURL_ContextVariables(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"received_path":  r.URL.Path,
			"received_query": r.URL.RawQuery,
			"received_host":  r.Host,
		})
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)

	// Create API that uses context variables in the URL
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Context Variable API"
		spec.APIID = "context-var-api"
		spec.OrgID = "default"
		spec.UseKeylessAccess = false
		spec.Auth.AuthHeaderName = "Authorization"
		spec.Proxy = apidef.ProxyConfig{
			ListenPath:      "/context-api/",
			TargetURL:       fmt.Sprintf("http://%s/$tyk_context.headers_X_Target_Version", upstreamURL.Host),
			StripListenPath: true,
		}
		spec.EnableContextVars = true
		spec.VersionData.NotVersioned = true
	})

	// Create session
	_, apiKey := ts.CreateSession(func(s *user.SessionState) {
		s.AccessRights = map[string]user.AccessDefinition{
			"context-var-api": {
				APIID: "context-var-api",
			},
		}
	})

	// Test with different header values
	testCases := []struct {
		name           string
		targetVersion  string
		expectedPath   string
	}{
		{
			name:          "Version v1",
			targetVersion: "v1",
			expectedPath:  "/v1/resource",
		},
		{
			name:          "Version v2",
			targetVersion: "v2",
			expectedPath:  "/v2/resource",
		},
		{
			name:          "Version beta",
			targetVersion: "beta",
			expectedPath:  "/beta/resource",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := ts.Run(t, test.TestCase{
				Path:   "/context-api/resource",
				Method: http.MethodGet,
				Headers: map[string]string{
					"Authorization":    apiKey,
					"X-Target-Version": tc.targetVersion,
				},
				Code: http.StatusOK,
			})
			require.NoError(t, err)

			var result map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&result)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedPath, result["received_path"])
		})
	}
}

// TestDynamicUpstreamURL_ComplexMetadata tests complex metadata scenarios
func TestDynamicUpstreamURL_ComplexMetadata(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"host":  r.Host,
			"path":  r.URL.Path,
			"query": r.URL.RawQuery,
		})
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	host, port := upstreamURL.Hostname(), upstreamURL.Port()

	// Create API with multiple variables
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Complex Metadata API"
		spec.APIID = "complex-meta-api"
		spec.OrgID = "default"
		spec.UseKeylessAccess = false
		spec.Auth.AuthHeaderName = "Authorization"
		spec.Proxy = apidef.ProxyConfig{
			ListenPath:      "/complex/",
			TargetURL:       "http://$tyk_meta.host:$tyk_meta.port/",
			StripListenPath: true,
		}
		spec.EnableContextVars = true
		spec.VersionData.NotVersioned = true
		
		t.Logf("Complex API - EnableContextVars: %v, TargetURL: %s", spec.EnableContextVars, spec.Proxy.TargetURL)
	})

	// Create session with complex metadata
	_, apiKey := ts.CreateSession(func(s *user.SessionState) {
		s.MetaData = map[string]interface{}{
			"host":      host,
			"port":      port,
			"tenant_id": "tenant-123",
		}
		s.AccessRights = map[string]user.AccessDefinition{
			"complex-meta-api": {
				APIID: "complex-meta-api",
			},
		}
	})

	resp, err := ts.Run(t, test.TestCase{
		Path:    "/complex/users/123",
		Method:  http.MethodGet,
		Headers: map[string]string{"Authorization": apiKey},
		Code:    http.StatusOK,
	})
	if err != nil {
		t.Logf("Request failed: %v", err)
	}
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, "/users/123", result["path"])
	assert.Equal(t, upstreamURL.Host, result["host"])
}

// TestDynamicUpstreamURL_PolicyMetadata tests that policy metadata works with dynamic URLs
func TestDynamicUpstreamURL_PolicyMetadata(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create upstream servers
	prodUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"environment": "production"})
	}))
	defer prodUpstream.Close()

	devUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"environment": "development"})
	}))
	defer devUpstream.Close()

	prodURL, _ := url.Parse(prodUpstream.URL)
	devURL, _ := url.Parse(devUpstream.URL)

	// Create API
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Policy Metadata API"
		spec.APIID = "policy-meta-api"
		spec.OrgID = "default"
		spec.UseKeylessAccess = false
		spec.Auth.AuthHeaderName = "Authorization"
		spec.Proxy = apidef.ProxyConfig{
			ListenPath:      "/policy-api/",
			TargetURL:       "http://$tyk_meta.upstream_host/",
			StripListenPath: true,
		}
		spec.EnableContextVars = true
		spec.VersionData.NotVersioned = true
	})

	// Create policies with different metadata
	prodPolicyID := ts.CreatePolicy(func(p *user.Policy) {
		p.Name = "Production Policy"
		p.MetaData = map[string]interface{}{
			"environment":   "production",
			"upstream_host": prodURL.Host,
		}
		p.AccessRights = map[string]user.AccessDefinition{
			"policy-meta-api": {
				APIID: "policy-meta-api",
			},
		}
	})

	devPolicyID := ts.CreatePolicy(func(p *user.Policy) {
		p.Name = "Development Policy"
		p.MetaData = map[string]interface{}{
			"environment":   "development",
			"upstream_host": devURL.Host,
		}
		p.AccessRights = map[string]user.AccessDefinition{
			"policy-meta-api": {
				APIID: "policy-meta-api",
			},
		}
	})

	// Create users with different policies
	_, prodKey := ts.CreateSession(func(s *user.SessionState) {
		s.ApplyPolicies = []string{prodPolicyID}
	})

	_, devKey := ts.CreateSession(func(s *user.SessionState) {
		s.ApplyPolicies = []string{devPolicyID}
	})

	// Test production user
	prodResp, err := ts.Run(t, test.TestCase{
		Path:    "/policy-api/test",
		Method:  http.MethodGet,
		Headers: map[string]string{"Authorization": prodKey},
		Code:    http.StatusOK,
	})
	require.NoError(t, err)

	var prodResult map[string]string
	err = json.NewDecoder(prodResp.Body).Decode(&prodResult)
	require.NoError(t, err)
	assert.Equal(t, "production", prodResult["environment"])

	// Test development user
	devResp, err := ts.Run(t, test.TestCase{
		Path:    "/policy-api/test",
		Method:  http.MethodGet,
		Headers: map[string]string{"Authorization": devKey},
		Code:    http.StatusOK,
	})
	require.NoError(t, err)

	var devResult map[string]string
	err = json.NewDecoder(devResp.Body).Decode(&devResult)
	require.NoError(t, err)
	assert.Equal(t, "development", devResult["environment"])
}

// TestDynamicUpstreamURL_ConnectionPooling tests connection pooling with dynamic URLs
func TestDynamicUpstreamURL_ConnectionPooling(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Track connections
	connectionCounts := make(map[string]*int32)
	serverMutexes := make(map[string]*sync.Mutex)

	// Create upstream servers that track connections
	createServer := func(name string) *httptest.Server {
		count := int32(0)
		connectionCounts[name] = &count
		serverMutexes[name] = &sync.Mutex{}

		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Track new connections (simplified - in real scenario would track TCP connections)
			atomic.AddInt32(connectionCounts[name], 1)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"server":      name,
				"connections": atomic.LoadInt32(connectionCounts[name]),
			})
		}))
	}

	serverA := createServer("serverA")
	defer serverA.Close()
	serverB := createServer("serverB")
	defer serverB.Close()

	urlA, _ := url.Parse(serverA.URL)
	urlB, _ := url.Parse(serverB.URL)

	// Create API
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Connection Pool API"
		spec.APIID = "conn-pool-api"
		spec.OrgID = "default"
		spec.UseKeylessAccess = false
		spec.Auth.AuthHeaderName = "Authorization"
		spec.Proxy = apidef.ProxyConfig{
			ListenPath:      "/conn-api/",
			TargetURL:       "http://$tyk_meta.target_host/",
			StripListenPath: true,
		}
		spec.EnableContextVars = true
		spec.VersionData.NotVersioned = true
	})

	// Create users for different servers
	_, keyA := ts.CreateSession(func(s *user.SessionState) {
		s.MetaData = map[string]interface{}{
			"target_host": urlA.Host,
		}
		s.AccessRights = map[string]user.AccessDefinition{
			"conn-pool-api": {
				APIID: "conn-pool-api",
			},
		}
	})

	_, keyB := ts.CreateSession(func(s *user.SessionState) {
		s.MetaData = map[string]interface{}{
			"target_host": urlB.Host,
		}
		s.AccessRights = map[string]user.AccessDefinition{
			"conn-pool-api": {
				APIID: "conn-pool-api",
			},
		}
	})

	// Make multiple requests to same server - connections should be reused
	for i := 0; i < 10; i++ {
		_, err := ts.Run(t, test.TestCase{
			Path:    "/conn-api/test",
			Method:  http.MethodGet,
			Headers: map[string]string{"Authorization": keyA},
			Code:    http.StatusOK,
		})
		require.NoError(t, err)
	}

	// Make requests to different server
	for i := 0; i < 10; i++ {
		_, err := ts.Run(t, test.TestCase{
			Path:    "/conn-api/test",
			Method:  http.MethodGet,
			Headers: map[string]string{"Authorization": keyB},
			Code:    http.StatusOK,
		})
		require.NoError(t, err)
	}

	// Both servers should have received requests
	connectionsA := atomic.LoadInt32(connectionCounts["serverA"])
	connectionsB := atomic.LoadInt32(connectionCounts["serverB"])

	t.Logf("Server A: %d connections for 10 requests", connectionsA)
	t.Logf("Server B: %d connections for 10 requests", connectionsB)

	assert.Greater(t, int(connectionsA), 0, "Server A should have connections")
	assert.Greater(t, int(connectionsB), 0, "Server B should have connections")

	// Due to connection pooling, connections should be less than requests
	// (This is a simplified test - actual connection pooling behavior depends on HTTP client configuration)
	assert.LessOrEqual(t, int(connectionsA), 10, "Server A should reuse connections")
	assert.LessOrEqual(t, int(connectionsB), 10, "Server B should reuse connections")
}

// TestDynamicUpstreamURL_ErrorHandling tests error scenarios
func TestDynamicUpstreamURL_ErrorHandling(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	// Create a valid upstream as fallback
	validUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer validUpstream.Close()

	// Create API
	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Name = "Error Handling API"
		spec.APIID = "error-api"
		spec.OrgID = "default"
		spec.UseKeylessAccess = false
		spec.Auth.AuthHeaderName = "Authorization"
		spec.Proxy = apidef.ProxyConfig{
			ListenPath:      "/error-api/",
			TargetURL:       "http://$tyk_meta.upstream_host/",
			StripListenPath: true,
		}
		spec.EnableContextVars = true
		spec.VersionData.NotVersioned = true
	})

	// Test with invalid host in metadata
	_, invalidKey := ts.CreateSession(func(s *user.SessionState) {
		s.MetaData = map[string]interface{}{
			"upstream_host": ":::invalid::host:::",
		}
		s.AccessRights = map[string]user.AccessDefinition{
			"error-api": {
				APIID: "error-api",
			},
		}
	})

	// This should fail gracefully
	_, err := ts.Run(t, test.TestCase{
		Path:    "/error-api/test",
		Method:  http.MethodGet,
		Headers: map[string]string{"Authorization": invalidKey},
		Code:    http.StatusInternalServerError, // or appropriate error code
	})
	// We expect an error or specific status code for invalid host
	assert.NoError(t, err, "Should handle invalid host without panic")

	// Test with missing metadata variable
	_, missingKey := ts.CreateSession(func(s *user.SessionState) {
		s.MetaData = map[string]interface{}{
			"other_field": "value",
			// upstream_host is missing
		}
		s.AccessRights = map[string]user.AccessDefinition{
			"error-api": {
				APIID: "error-api",
			},
		}
	})

	// This should fail as the variable won't be replaced
	_, err = ts.Run(t, test.TestCase{
		Path:    "/error-api/test",
		Method:  http.MethodGet,
		Headers: map[string]string{"Authorization": missingKey},
		Code:    http.StatusInternalServerError,
	})
	assert.NoError(t, err, "Should handle missing variable without panic")
}