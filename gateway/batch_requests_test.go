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
			FunctionSourceType:   "blob",
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
			FunctionSourceType:   "blob",
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
