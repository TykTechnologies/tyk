package gateway

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

var (
	testBundlesPath = filepath.Join(testMiddlewarePath, "bundles")
)

func pkgPath() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Dir(filename) + "./.."
}

var grpcBundleWithAuthCheck = map[string]string{
	"manifest.json": `
		{
		    "file_list": [],
		    "custom_middleware": {
		        "driver": "grpc",
		        "auth_check": {
		            "name": "MyAuthHook"
		        }
		    },
			"checksum": "d41d8cd98f00b204e9800998ecf8427e"
		}
	`,
}

var bundleWithBadSignature = map[string]string{
	"manifest.json": `
		{
		    "file_list": [],
		    "custom_middleware": {
		        "driver": "grpc",
		        "auth_check": {
		            "name": "MyAuthHook"
		        }
		    },
			"checksum": "d41d8cd98f00b204e9800998ecf8427e",
			"signature": "dGVzdC1wdWJsaWMta2V5"
		}
	`,
}

func TestBundleLoader(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	bundleID := ts.RegisterBundle("grpc_with_auth_check", grpcBundleWithAuthCheck)
	unsignedBundleID := ts.RegisterBundle("grpc_with_auth_check_signed", grpcBundleWithAuthCheck)
	badSignatureBundleID := ts.RegisterBundle("bad_signature", bundleWithBadSignature)

	t.Run("Nonexistent bundle", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				CustomMiddlewareBundle: "nonexistent.zip",
			},
		}
		err := ts.Gw.loadBundle(spec)
		assert.Error(t, err)
	})

	t.Run("Existing bundle with auth check", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				CustomMiddlewareBundle: bundleID,
			},
		}
		err := ts.Gw.loadBundle(spec)
		assert.NoError(t, err)

		bundleNameHash := md5.New()
		io.WriteString(bundleNameHash, spec.CustomMiddlewareBundle)
		bundleDir := fmt.Sprintf("%x", bundleNameHash.Sum(nil))
		savedBundlePath := filepath.Join(testBundlesPath, bundleDir)
		if _, err = os.Stat(savedBundlePath); os.IsNotExist(err) {
			t.Fatalf("Bundle wasn't saved to disk: %s", err.Error())
		}

		// Check bundle contents:
		if spec.CustomMiddleware.AuthCheck.Name != "MyAuthHook" {
			t.Fatalf("Auth check function doesn't match: got %s, expected %s\n", spec.CustomMiddleware.AuthCheck.Name, "MyAuthHook")
		}
		if string(spec.CustomMiddleware.Driver) != "grpc" {
			t.Fatalf("Driver doesn't match: got %s, expected %s\n", spec.CustomMiddleware.Driver, "grpc")
		}
	})

	t.Run("bundle disabled with bundle value", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				CustomMiddlewareBundle:         "bundle.zip",
				CustomMiddlewareBundleDisabled: true,
			},
		}
		err := ts.Gw.loadBundle(spec)
		assert.Empty(t, spec.CustomMiddleware)
		assert.NoError(t, err)
	})

	t.Run("bundle enabled with empty bundle value", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				CustomMiddlewareBundle:         "",
				CustomMiddlewareBundleDisabled: false,
			},
		}
		err := ts.Gw.loadBundle(spec)
		assert.Empty(t, spec.CustomMiddleware)
		assert.NoError(t, err)
	})

	t.Run("load bundle should not load bundle nor error when the gateway instance is a management node", func(t *testing.T) {
		customTs := StartTest(func(globalConf *config.Config) {
			globalConf.ManagementNode = true
		})

		t.Cleanup(customTs.Close)
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				CustomMiddlewareBundle:         "some-bundle",
				CustomMiddlewareBundleDisabled: false,
			},
		}
		err := customTs.Gw.loadBundle(spec)
		assert.Empty(t, spec.CustomMiddleware)
		assert.NoError(t, err)
	})

	t.Run("Load bundle fails if public key path is set but no signature is provided", func(t *testing.T) {
		cfg := ts.Gw.GetConfig()
		cfg.PublicKeyPath = "random/path/to/public.key"
		ts.Gw.SetConfig(cfg)

		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				CustomMiddlewareBundle: unsignedBundleID,
			},
		}
		err := ts.Gw.loadBundle(spec)

		assert.ErrorContains(t, err, "Bundle isn't signed")
	})

	t.Run("Load bundle fails if public key path is set but signature verification fails", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() failed: %v", err)
		}
		publicKey := &privateKey.PublicKey

		publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			t.Fatalf("x509.MarshalPKIXPublicKey() failed: %v", err)
		}

		pemBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyDER,
		}

		tmpfile, err := os.CreateTemp("", "example")
		if err != nil {
			t.Fatalf("os.CreateTemp() failed: %v", err)
		}
		defer tmpfile.Close()
		defer os.Remove(tmpfile.Name())

		if err := pem.Encode(tmpfile, pemBlock); err != nil {
			t.Fatalf("pem.Encode() failed: %v", err)
		}

		cfg := ts.Gw.GetConfig()
		cfg.PublicKeyPath = tmpfile.Name()
		ts.Gw.SetConfig(cfg)

		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				CustomMiddlewareBundle: badSignatureBundleID,
			},
		}
		err = ts.Gw.loadBundle(spec)

		assert.ErrorContains(t, err, "crypto/rsa: verification error")
	})
}

func TestBundleFetcher(t *testing.T) {
	bundleID := "testbundle"
	ts := StartTest(nil)
	defer ts.Close()

	t.Run("bundle fetch scenario with api load", func(t *testing.T) {
		t.Run("do not skip when fetch is successful", func(t *testing.T) {
			manifest := map[string]string{
				"manifest.json": `
		{
		    "file_list": [],
		    "custom_middleware": {
		        "driver": "otto",
		        "pre": [{
		            "name": "testTykMakeHTTPRequest",
		            "path": "middleware.js"
		        }]
		    },
			"checksum": "d41d8cd98f00b204e9800998ecf8427e"
		}
	`,
				"middleware.js": `
	var testTykMakeHTTPRequest = new TykJS.TykMiddleware.NewMiddleware({})

	testTykMakeHTTPRequest.NewProcessRequest(function(request, session, spec) {
		var newRequest = {
			"Method": "GET",
			"Headers": {"Accept": "application/json"},
			"Domain": spec.config_data.base_url,
			"Resource": "/api/get?param1=dummy"
		}

		var resp = TykMakeHttpRequest(JSON.stringify(newRequest));
		var usableResponse = JSON.parse(resp);

		if(usableResponse.Code > 400) {
			request.ReturnOverrides.ResponseCode = usableResponse.code
			request.ReturnOverrides.ResponseError = "error"
		}

		request.Body = usableResponse.Body

		return testTykMakeHTTPRequest.ReturnData(request, {})
	});
	`}
			ts := StartTest(nil)
			defer ts.Close()
			bundle := ts.RegisterBundle("jsvm_make_http_request", manifest)

			ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.Proxy.ListenPath = "/sample"
				spec.ConfigData = map[string]interface{}{
					"base_url": ts.URL,
				}
				spec.CustomMiddlewareBundle = bundle
			}, func(spec *APISpec) {
				spec.Proxy.ListenPath = "/api"
			})

		})

		t.Run("skip when fetch is not successful", func(t *testing.T) {
			globalConf := ts.Gw.GetConfig()
			globalConf.BundleBaseURL = "http://some-invalid-path"
			globalConf.BundleInsecureSkipVerify = false
			ts.Gw.SetConfig(globalConf)
			_ = ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
				spec.CustomMiddlewareBundle = bundleID
			})
			assert.Empty(t, ts.Gw.apiSpecs)
		})
	})
}

var overrideResponsePython = map[string]string{
	"manifest.json": `
		{
		    "file_list": [
		        "middleware.py"
		    ],
		    "custom_middleware": {
		        "driver": "python",
		        "pre": [{
		            "name": "MyRequestHook"
		        }]
		    },
			"checksum": "81f585cdf7bf352e3c33ed62396b1e8e"
		}
	`,
	"middleware.py": `
from tyk.decorators import *
from gateway import TykGateway as tyk

@Hook
def MyRequestHook(request, response, session, metadata, spec):
	request.object.return_overrides.headers['X-Foo'] = 'Bar'
	request.object.return_overrides.response_code = int(request.object.params["status"])

	if request.object.params["response_body"] == "true":
		request.object.return_overrides.response_body = "foobar"
	else:
		request.object.return_overrides.response_error = "{\"foo\": \"bar\"}"

	if request.object.params["override"]:
		request.object.return_overrides.override_error = True

	return request, session
`,
}

var overrideResponseJSVM = map[string]string{
	"manifest.json": `
{
    "file_list": [],
    "custom_middleware": {
        "driver": "otto",
        "pre": [{
            "name": "pre",
            "path": "pre.js"
        }]
    },
	"checksum": "d41d8cd98f00b204e9800998ecf8427e"
}
`,
	"pre.js": `
var pre = new TykJS.TykMiddleware.NewMiddleware({});

pre.NewProcessRequest(function(request, session) {
	if (request.Params["response_body"]) {
		request.ReturnOverrides.ResponseBody = 'foobar'
	} else {
		request.ReturnOverrides.ResponseError = '{"foo": "bar"}'
	}

	request.ReturnOverrides.ResponseCode = parseInt(request.Params["status"])
	request.ReturnOverrides.ResponseHeaders = {"X-Foo": "Bar"}

	if (request.Params["override"]) {
		request.ReturnOverrides.OverrideError = true
	}
	return pre.ReturnData(request, {});
});
`,
}

func TestResponseOverride(t *testing.T) {
	pythonVersion := test.GetPythonVersion()

	ts := StartTest(nil, TestConfig{
		CoprocessConfig: config.CoProcessConfig{
			EnableCoProcess:  true,
			PythonPathPrefix: pkgPath(),
			PythonVersion:    pythonVersion,
		}})
	defer ts.Close()

	customHeader := map[string]string{"X-Foo": "Bar"}
	customError := `{"foo": "bar"}`
	customBody := `foobar`

	testOverride := func(t *testing.T, bundle string) {
		ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
			spec.Proxy.ListenPath = "/test/"
			spec.UseKeylessAccess = true
			spec.CustomMiddlewareBundle = bundle
		})

		ts.Run(t, []test.TestCase{
			{Path: "/test/?status=200", Code: 200, BodyMatch: customError, HeadersMatch: customHeader},
			{Path: "/test/?status=200&response_body=true", Code: 200, BodyMatch: customBody, HeadersMatch: customHeader},
			{Path: "/test/?status=400", Code: 400, BodyMatch: `"error": "`, HeadersMatch: customHeader},
			{Path: "/test/?status=400&response_body=true", Code: 400, BodyMatch: `"error": "foobar"`, HeadersMatch: customHeader},
			{Path: "/test/?status=401", Code: 401, BodyMatch: `"error": "`, HeadersMatch: customHeader},
			{Path: "/test/?status=400&override=true", Code: 400, BodyMatch: customError, HeadersMatch: customHeader},
			{Path: "/test/?status=400&override=true&response_body=true", Code: 400, BodyMatch: customBody, HeadersMatch: customHeader},
			{Path: "/test/?status=401&override=true", Code: 401, BodyMatch: customError, HeadersMatch: customHeader},
		}...)
	}
	t.Run("Python", func(t *testing.T) {
		testOverride(t, ts.RegisterBundle("python_override", overrideResponsePython))
	})

	t.Run("JSVM", func(t *testing.T) {
		testOverride(t, ts.RegisterBundle("jsvm_override", overrideResponseJSVM))
	})
}

func TestBundle_Pull(t *testing.T) {
	// Currently this test is impacted by global scope, and skipped.
	// This test is skipped due to changed test environment for
	// the backoff and retries values; it's likely HTTPBundleGetter
	// should include the backoff and retry values to make this pass.
	t.Skip()

	testCases := []struct {
		name             string
		expectedAttempts int
		shouldErr        bool
	}{
		{
			name:             "bundle downloaded at first attempt",
			expectedAttempts: 1,
			shouldErr:        false,
		},
		{
			// failed the 2 first times
			name:             "bundle downloaded at third attempt",
			expectedAttempts: 3,
			shouldErr:        false,
		},
		{
			// should try 5 times, afterwards it will fail
			name:             "bundle download failed",
			expectedAttempts: 5,
			shouldErr:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attempts := 0

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts++
				if tc.expectedAttempts > attempts || tc.shouldErr {
					// simulate file not found, so it will throw err
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer ts.Close()

			getter := &HTTPBundleGetter{
				URL:                ts.URL,
				InsecureSkipVerify: false,
			}
			_, err := pullBundle(getter, 0)

			didErr := err != nil
			assert.Equal(t, tc.expectedAttempts, attempts)
			assert.Equal(t, tc.shouldErr, didErr)
		})
	}
}

func TestBundle_Verify(t *testing.T) {

	tests := []struct {
		name    string
		bundle  Bundle
		wantErr bool
	}{
		{
			name: "bundle with invalid public key path",
			bundle: Bundle{
				Name: "test",
				Data: []byte("test"),
				Path: "/test/test.zip",
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddlewareBundle: "test-mw-bundle",
					},
				},
				Manifest: apidef.BundleManifest{
					Signature: "test-signature",
				},
				Gw: &Gateway{},
			},
			wantErr: true,
		},
		{
			name: "bundle without signature",
			bundle: Bundle{
				Name: "test",
				Data: []byte("test"),
				Path: "/test/test.zip",
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddlewareBundle: "test-mw-bundle",
					},
				},
				Manifest: apidef.BundleManifest{
					Signature: "",
				},
				Gw: &Gateway{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := tt.bundle

			globalConf := config.Config{}
			globalConf.PublicKeyPath = "test"
			b.Gw.SetConfig(globalConf)

			if err := b.Verify(); (err != nil) != tt.wantErr {
				t.Errorf("Bundle.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
