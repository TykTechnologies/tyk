package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/TykTechnologies/tyk/certs"

	"github.com/valyala/fasthttp"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/test"
)

const testBatchRequest = `{
	"requests": [
	{
		"method": "GET",
		"headers": {
			"test-header-1": "test-1",
			"test-header-2": "test-2"
		},
		"relative_url": "get/?param1=this"
	},
	{
		"method": "POST",
		"body": "TEST BODY",
		"relative_url": "post/"
	},
	{
		"method": "PUT",
		"relative_url": "put/"
	}
	],
	"suppress_parallel_execution": true
}`

// Verifies: STK-REQ-104, SYS-REQ-192, SW-REQ-180
// STK-REQ-104:STK-REQ-104-AC-01:acceptance
// STK-REQ-104:nominal:nominal
// STK-REQ-104:boundary:nominal
// STK-REQ-104:error_handling:negative
// STK-REQ-104:error_handling:nominal
// STK-REQ-104:encoding_safety:nominal
// STK-REQ-104:determinism:nominal
// SYS-REQ-192:nominal:nominal
// SYS-REQ-192:boundary:nominal
// SYS-REQ-192:error_handling:negative
// SYS-REQ-192:error_handling:nominal
// SYS-REQ-192:encoding_safety:nominal
// SYS-REQ-192:determinism:nominal
// SW-REQ-180:nominal:nominal
// SW-REQ-180:boundary:nominal
// SW-REQ-180:error_handling:negative
// SW-REQ-180:error_handling:nominal
// SW-REQ-180:encoding_safety:nominal
// SW-REQ-180:determinism:nominal
func TestBatch(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/v1/"
		spec.EnableBatchRequestSupport = true
	})

	ts.Run(t, []test.TestCase{
		{Method: "POST", Path: "/v1/tyk/batch/", Data: `{"requests":[]}`, Code: 200, BodyMatch: `\[\]`},
		{Method: "POST", Path: "/v1/tyk/batch/", Data: "malformed", Code: 400},
		{Method: "POST", Path: "/v1/tyk/batch/", Data: testBatchRequest, Code: 200},
	}...)

	resp, _ := ts.Do(test.TestCase{Method: "POST", Path: "/v1/tyk/batch/", Data: testBatchRequest})
	if resp != nil {
		body, _ := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()

		var batchResponse []map[string]json.RawMessage
		if err := json.Unmarshal(body, &batchResponse); err != nil {
			t.Fatal(err)
		}

		if len(batchResponse) != 3 {
			t.Errorf("Length not match: %d", len(batchResponse))
		}

		if string(batchResponse[0]["relative_url"]) != `"get/?param1=this"` {
			t.Error("Url order not match:", string(batchResponse[0]["relative_url"]))
		}
	}
}

const virtBatchTest = `function batchTest(request, session, config) {
    // Set up a response object
    var response = {
        Body: "",
        Headers: {
            "content-type": "application/json"
        },
        Code: 202
    }

    // Batch request
    var batch = {
        "requests": [
            {
                "method": "GET",
                "headers": {
                    "X-CertificateOuid": "X-CertificateOuid"
                },
                "body": "",
                "relative_url": "{upstream_URL}"
            },
            {
                "method": "GET",
                "headers": {
                    "X-CertificateOuid": "X-CertificateOuid"
                },
                "body": "",
                "relative_url": "{upstream_URL}"
            }
        ],
        "suppress_parallel_execution": false
    }

    var newBody = TykBatchRequest(JSON.stringify(batch))
    var asJS = JSON.parse(newBody)
    for (var i in asJS) {
        if (asJS[i].code == 0) {
            response.Code = 500
        }
    }
    return TykJsResponse(response, session.meta_data)
}`

// Verifies: STK-REQ-104, SYS-REQ-192, SW-REQ-180
// STK-REQ-104:STK-REQ-104-AC-01:acceptance
// STK-REQ-104:nominal:nominal
// STK-REQ-104:boundary:nominal
// STK-REQ-104:error_handling:negative
// STK-REQ-104:error_handling:nominal
// STK-REQ-104:encoding_safety:nominal
// SYS-REQ-192:nominal:nominal
// SYS-REQ-192:boundary:nominal
// SYS-REQ-192:error_handling:negative
// SYS-REQ-192:error_handling:nominal
// SYS-REQ-192:encoding_safety:nominal
// SW-REQ-180:nominal:nominal
// SW-REQ-180:boundary:nominal
// SW-REQ-180:error_handling:negative
// SW-REQ-180:error_handling:nominal
// SW-REQ-180:encoding_safety:nominal
func TestVirtualEndpointBatch(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	_, _, combinedClientPEM, clientCert := certs.GenCertificate(&x509.Certificate{}, false)
	clientCert.Leaf, _ = x509.ParseCertificate(clientCert.Certificate[0])
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))

	// Mutual TLS protected upstream
	pool := x509.NewCertPool()
	pool.AddCert(clientCert.Leaf)
	upstream.TLS = &tls.Config{
		ClientAuth:         tls.RequireAndVerifyClientCert,
		ClientCAs:          pool,
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
	}

	upstream.StartTLS()
	defer upstream.Close()

	clientCertID, _ := ts.Gw.CertificateManager.Add(combinedClientPEM, "")
	defer ts.Gw.CertificateManager.Delete(clientCertID, "")

	js := strings.Replace(virtBatchTest, "{upstream_URL}", upstream.URL, 2)
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "https://")

	globalConf := ts.Gw.GetConfig()
	globalConf.Security.Certificates.Upstream = map[string]string{upstreamHost: clientCertID}
	ts.Gw.SetConfig(globalConf)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		virtualMeta := apidef.VirtualMeta{
			ResponseFunctionName: "batchTest",
			FunctionSourceType:   apidef.UseBlob,
			FunctionSourceURI:    base64.StdEncoding.EncodeToString([]byte(js)),
			Path:                 "/virt",
			Method:               "GET",
		}
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.UseExtendedPaths = true
			v.ExtendedPaths = apidef.ExtendedPathsSet{
				Virtual: []apidef.VirtualMeta{virtualMeta},
			}
		})
	})

	t.Run("Skip verification", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.ProxySSLInsecureSkipVerify = true
		ts.Gw.SetConfig(globalConf)

		ts.Run(t, test.TestCase{Path: "/virt", Code: 202})
	})

	t.Run("Verification required", func(t *testing.T) {
		globalConf := ts.Gw.GetConfig()
		globalConf.ProxySSLInsecureSkipVerify = false
		ts.Gw.SetConfig(globalConf)

		ts.Run(t, test.TestCase{Path: "/virt", Code: 500})
	})

}

// Verifies: STK-REQ-104, SYS-REQ-192, SW-REQ-180
// STK-REQ-104:STK-REQ-104-AC-01:acceptance
// STK-REQ-104:nominal:nominal
// STK-REQ-104:boundary:nominal
// STK-REQ-104:encoding_safety:nominal
// SYS-REQ-192:nominal:nominal
// SYS-REQ-192:boundary:nominal
// SYS-REQ-192:encoding_safety:nominal
// SW-REQ-180:nominal:nominal
// SW-REQ-180:boundary:nominal
// SW-REQ-180:encoding_safety:nominal
func TestBatchIgnoreCanonicalHeaderKey(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if l, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
	}
	defer l.Close()
	var header atomic.Value
	header.Store("")
	requestHandler := func(ctx *fasthttp.RequestCtx) {
		ctx.Request.Header.DisableNormalizing()
		header.Store(string(ctx.Request.Header.Peek(NonCanonicalHeaderKey)))
	}
	srv := &fasthttp.Server{
		Handler:                       requestHandler,
		DisableHeaderNamesNormalizing: true,
	}
	go func() {
		srv.Serve(l)
	}()

	upstream := "http://" + l.Addr().String()

	js := strings.Replace(virtBatchTest, "{upstream_URL}", upstream, 2)
	c := ts.Gw.GetConfig()
	c.IgnoreCanonicalMIMEHeaderKey = true
	ts.Gw.SetConfig(c)

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		virtualMeta := apidef.VirtualMeta{
			ResponseFunctionName: "batchTest",
			FunctionSourceType:   apidef.UseBlob,
			FunctionSourceURI:    base64.StdEncoding.EncodeToString([]byte(js)),
			Path:                 "/virt",
			Method:               "GET",
		}
		UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
			v.UseExtendedPaths = true
			v.ExtendedPaths = apidef.ExtendedPathsSet{
				Virtual: []apidef.VirtualMeta{virtualMeta},
			}
		})
	})

	ts.Run(t, test.TestCase{Path: "/virt", Code: 202})
	got := header.Load().(string)
	if got != NonCanonicalHeaderKey {
		t.Errorf("expected %q got %q", NonCanonicalHeaderKey, got)
	}
}

// Verifies: STK-REQ-104, SYS-REQ-192, SW-REQ-180
// MCDC SYS-REQ-192: gateway_batch_endpoint_handling_determined=T, gateway_batch_request_construction_determined=T, gateway_batch_execution_collation_determined=T, gateway_batch_manual_virtual_endpoint_determined=T, gateway_batch_tls_outcomes_determined=T, gateway_batch_reply_encoding_determined=T => TRUE
// MCDC SW-REQ-180: gateway_batch_endpoint_handling_determined=T, gateway_batch_request_construction_determined=T, gateway_batch_execution_collation_determined=T, gateway_batch_manual_virtual_endpoint_determined=T, gateway_batch_tls_outcomes_determined=T, gateway_batch_reply_encoding_determined=T => TRUE
func TestBatchRequestsReqProof(t *testing.T) {
	t.Run("batch endpoint handles malformed empty and sequential requests", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/reqproof-batch/"
			spec.EnableBatchRequestSupport = true
		})

		ts.Run(t, []test.TestCase{
			{Method: "POST", Path: "/reqproof-batch/tyk/batch/", Data: `{"requests":[]}`, Code: http.StatusOK, BodyMatch: `\[\]`},
			{Method: "POST", Path: "/reqproof-batch/tyk/batch/", Data: "malformed", Code: http.StatusBadRequest},
			{Method: "POST", Path: "/reqproof-batch/tyk/batch/", Data: testBatchRequest, Code: http.StatusOK},
		}...)

		resp, _ := ts.Do(test.TestCase{Method: "POST", Path: "/reqproof-batch/tyk/batch/", Data: testBatchRequest})
		if resp == nil {
			t.Fatal("expected batch response")
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(body) {
			t.Fatalf("expected valid JSON batch reply: %s", string(body))
		}

		var batchResponse []map[string]json.RawMessage
		if err := json.Unmarshal(body, &batchResponse); err != nil {
			t.Fatal(err)
		}
		if len(batchResponse) != 3 {
			t.Fatalf("expected 3 batch responses, got %d", len(batchResponse))
		}
		if string(batchResponse[0]["relative_url"]) != `"get/?param1=this"` {
			t.Fatalf("expected first sequential URL to be get/?param1=this, got %s", string(batchResponse[0]["relative_url"]))
		}
	})

	t.Run("manual virtual endpoint applies TLS outcomes", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		_, _, combinedClientPEM, clientCert := certs.GenCertificate(&x509.Certificate{}, false)
		clientCert.Leaf, _ = x509.ParseCertificate(clientCert.Certificate[0])
		upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

		pool := x509.NewCertPool()
		pool.AddCert(clientCert.Leaf)
		upstream.TLS = &tls.Config{
			ClientAuth:         tls.RequireAndVerifyClientCert,
			ClientCAs:          pool,
			InsecureSkipVerify: true,
			MaxVersion:         tls.VersionTLS12,
		}

		upstream.StartTLS()
		defer upstream.Close()

		clientCertID, _ := ts.Gw.CertificateManager.Add(combinedClientPEM, "")
		defer ts.Gw.CertificateManager.Delete(clientCertID, "")

		js := strings.Replace(virtBatchTest, "{upstream_URL}", upstream.URL, 2)
		upstreamHost := strings.TrimPrefix(upstream.URL, "https://")

		globalConf := ts.Gw.GetConfig()
		globalConf.Security.Certificates.Upstream = map[string]string{upstreamHost: clientCertID}
		ts.Gw.SetConfig(globalConf)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			virtualMeta := apidef.VirtualMeta{
				ResponseFunctionName: "batchTest",
				FunctionSourceType:   apidef.UseBlob,
				FunctionSourceURI:    base64.StdEncoding.EncodeToString([]byte(js)),
				Path:                 "/reqproof-virt",
				Method:               "GET",
			}
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.UseExtendedPaths = true
				v.ExtendedPaths = apidef.ExtendedPathsSet{
					Virtual: []apidef.VirtualMeta{virtualMeta},
				}
			})
		})

		globalConf = ts.Gw.GetConfig()
		globalConf.ProxySSLInsecureSkipVerify = true
		ts.Gw.SetConfig(globalConf)
		ts.Run(t, test.TestCase{Path: "/reqproof-virt", Code: http.StatusAccepted})

		globalConf = ts.Gw.GetConfig()
		globalConf.ProxySSLInsecureSkipVerify = false
		ts.Gw.SetConfig(globalConf)
		ts.Run(t, test.TestCase{Path: "/reqproof-virt", Code: http.StatusInternalServerError})
	})

	t.Run("manual batch preserves configured non-canonical headers", func(t *testing.T) {
		ts := StartTest(nil)
		defer ts.Close()

		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()

		var header atomic.Value
		header.Store("")
		srv := &fasthttp.Server{
			Handler: func(ctx *fasthttp.RequestCtx) {
				ctx.Request.Header.DisableNormalizing()
				header.Store(string(ctx.Request.Header.Peek(NonCanonicalHeaderKey)))
			},
			DisableHeaderNamesNormalizing: true,
		}
		go func() {
			_ = srv.Serve(l)
		}()
		defer srv.Shutdown()

		upstream := "http://" + l.Addr().String()
		js := strings.Replace(virtBatchTest, "{upstream_URL}", upstream, 2)

		c := ts.Gw.GetConfig()
		c.IgnoreCanonicalMIMEHeaderKey = true
		ts.Gw.SetConfig(c)

		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/"
			virtualMeta := apidef.VirtualMeta{
				ResponseFunctionName: "batchTest",
				FunctionSourceType:   apidef.UseBlob,
				FunctionSourceURI:    base64.StdEncoding.EncodeToString([]byte(js)),
				Path:                 "/reqproof-header",
				Method:               "GET",
			}
			UpdateAPIVersion(spec, "v1", func(v *apidef.VersionInfo) {
				v.UseExtendedPaths = true
				v.ExtendedPaths = apidef.ExtendedPathsSet{
					Virtual: []apidef.VirtualMeta{virtualMeta},
				}
			})
		})

		ts.Run(t, test.TestCase{Path: "/reqproof-header", Code: http.StatusAccepted})
		got := header.Load().(string)
		if got != NonCanonicalHeaderKey {
			t.Fatalf("expected %q got %q", NonCanonicalHeaderKey, got)
		}
	})
}
