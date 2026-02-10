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

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		pemfile := createPEMFile(t)
		t.Cleanup(func() {
			_ = pemfile.Close()
			_ = os.Remove(pemfile.Name())
		})

		cfg := ts.Gw.GetConfig()
		cfg.PublicKeyPath = pemfile.Name()
		ts.Gw.SetConfig(cfg)

		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				CustomMiddlewareBundle: badSignatureBundleID,
			},
		}
		err := ts.Gw.loadBundle(spec)

		assert.ErrorContains(t, err, "crypto/rsa: verification error")
	})

	t.Run("should always validate manifest.json, even if it already exists on the filesystem", func(t *testing.T) {
		pemfile := createPEMFile(t)
		t.Cleanup(func() {
			_ = pemfile.Close()
			_ = os.Remove(pemfile.Name())
		})

		cfg := ts.Gw.GetConfig()
		cfg.PublicKeyPath = pemfile.Name()
		ts.Gw.SetConfig(cfg)

		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				CustomMiddlewareBundle: "bundle-unverifiable.zip",
			},
		}

		bundlePath := ts.Gw.getBundleDestPath(spec)

		memFs := afero.NewMemMapFs()
		err := memFs.MkdirAll(bundlePath, 0755)
		require.NoError(t, err)

		manifestFile, err := memFs.Create(filepath.Join(bundlePath, "manifest.json"))
		require.NoError(t, err)
		_, err = manifestFile.WriteString(`{
		    "file_list": [
				"plugin.py"
			],
		    "custom_middleware": {
		        "driver": "python",
		        "auth_check": {
		            "name": "MyAuthHook"
		        }
		    },
			"checksum": "d41d8cd98f00b204e9800998ecf8427e",
			"signature": "dGVzdC1wdWJsaWMta2V5"
		}`)
		require.NoError(t, err)

		_, err = memFs.Create(filepath.Join(bundlePath, "plugin.py"))
		require.NoError(t, err)

		err = ts.Gw.loadBundleWithFs(spec, memFs)
		assert.ErrorContains(t, err, "crypto/rsa: verification error")
	})

	t.Run("load bundle fails if manifest can't be found locally", func(t *testing.T) {
		spec := &APISpec{
			APIDefinition: &apidef.APIDefinition{
				CustomMiddlewareBundle: "bundle.zip",
			},
		}

		bundlePath := ts.Gw.getBundleDestPath(spec)

		memFS := afero.NewMemMapFs()
		err := memFS.MkdirAll(bundlePath, 0755)
		require.NoError(t, err)

		_, err = memFS.Create(filepath.Join(bundlePath, "plugin.py"))
		require.NoError(t, err)

		err = ts.Gw.loadBundleWithFs(spec, memFS)
		assert.ErrorContains(t, err, "manifest.json: file does not exist")
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
		name           string
		bundle         Bundle
		setupFs        func(afero.Fs, string)
		usePublicKey   bool
		partialVerify  bool
		skipVerifCheck bool
		wantErr        bool
		wantErrContain string
	}{
		{
			name: "bundle with invalid public key path using DeepVerify",
			bundle: Bundle{
				Name: "test",
				Data: []byte("test"),
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
			usePublicKey:  true,
			partialVerify: false,
			wantErr:       true,
		},
		{
			name: "bundle without signature using DeepVerify",
			bundle: Bundle{
				Name: "test",
				Data: []byte("test"),
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
			usePublicKey:   true,
			partialVerify:  false,
			wantErr:        true,
			wantErrContain: "Bundle isn't signed",
		},
		{
			name: "valid checksum with empty file list using DeepVerify",
			bundle: Bundle{
				Name: "test",
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddlewareBundle: "test-mw-bundle",
					},
				},
				Manifest: apidef.BundleManifest{
					Checksum: "d41d8cd98f00b204e9800998ecf8427e", // MD5 of the empty string
					FileList: []string{},
				},
				Gw: &Gateway{},
			},
			usePublicKey:  false,
			partialVerify: false,
			wantErr:       false,
		},
		{
			name: "invalid checksum returns error using DeepVerify",
			bundle: Bundle{
				Name: "test",
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddlewareBundle: "test-mw-bundle",
					},
				},
				Manifest: apidef.BundleManifest{
					Checksum: "invalidchecksum123",
					FileList: []string{},
				},
				Gw: &Gateway{},
			},
			usePublicKey:   false,
			partialVerify:  false,
			wantErr:        true,
			wantErrContain: "invalid checksum",
		},
		{
			name: "file not found in file list using DeepVerify",
			bundle: Bundle{
				Name: "test",
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddlewareBundle: "test-mw-bundle",
					},
				},
				Manifest: apidef.BundleManifest{
					Checksum: "d41d8cd98f00b204e9800998ecf8427e",
					FileList: []string{"nonexistent.py"},
				},
				Gw: &Gateway{},
			},
			setupFs:       func(_ afero.Fs, _ string) {},
			usePublicKey:  false,
			partialVerify: false,
			wantErr:       true,
		},
		{
			name: "valid checksum with multiple files using DeepVerify",
			bundle: Bundle{
				Name: "test",
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddlewareBundle: "test-mw-bundle",
					},
				},
				Manifest: apidef.BundleManifest{
					// MD5 of "file1 contentfile2 content"
					Checksum: "1510d0e71b31de1c78fd9e823a7c6de9",
					FileList: []string{"file1.py", "file2.py"},
				},
				Gw: &Gateway{},
			},
			setupFs: func(fs afero.Fs, bundlePath string) {
				assert.NoError(t, afero.WriteFile(fs, filepath.Join(bundlePath, "file1.py"), []byte("file1 content"), 0644))
				assert.NoError(t, afero.WriteFile(fs, filepath.Join(bundlePath, "file2.py"), []byte("file2 content"), 0644))
			},
			usePublicKey:  false,
			partialVerify: false,
			wantErr:       false,
		},
		{
			name: "invalid base64 signature returns error using DeepVerify",
			bundle: Bundle{
				Name: "test",
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddlewareBundle: "test-mw-bundle",
					},
				},
				Manifest: apidef.BundleManifest{
					Checksum:  "d41d8cd98f00b204e9800998ecf8427e",
					FileList:  []string{},
					Signature: "!!!invalid-base64!!!",
				},
				Gw: &Gateway{},
			},
			usePublicKey:  true,
			partialVerify: false,
			wantErr:       true,
		},
		{
			name: "partial verify skips checksum when specified",
			bundle: Bundle{
				Name: "test",
				Spec: &APISpec{
					APIDefinition: &apidef.APIDefinition{
						CustomMiddlewareBundle: "test-mw-bundle",
					},
				},
				Manifest: apidef.BundleManifest{
					Checksum: "invalidchecksum",
					FileList: []string{},
				},
				Gw: &Gateway{},
			},
			usePublicKey:   true,
			partialVerify:  true,
			skipVerifCheck: true,
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := tt.bundle

			// Set up Gateway with BundleChecksumVerifier
			b.Gw.BundleChecksumVerifier = defaultBundleVerifyFunction

			globalConf := config.Config{}
			if tt.usePublicKey {
				pemfile := createPEMFile(t)
				t.Cleanup(func() {
					_ = pemfile.Close()
					_ = os.Remove(pemfile.Name())
				})
				globalConf.PublicKeyPath = pemfile.Name()
			}
			b.Gw.SetConfig(globalConf)

			fs := afero.NewMemMapFs()
			bundlePath := "/test/bundles/test-bundle"
			b.Path = bundlePath

			if err := fs.MkdirAll(bundlePath, 0755); err != nil {
				t.Fatalf("failed to create bundle directory: %v", err)
			}

			if tt.setupFs != nil {
				tt.setupFs(fs, bundlePath)
			}

			var err error
			if tt.partialVerify {
				err = b.PartialVerify(fs, tt.skipVerifCheck)
			} else {
				err = b.DeepVerify(fs)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("Bundle.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErrContain != "" && err != nil {
				assert.ErrorContains(t, err, tt.wantErrContain)
			}
		})
	}
}

func createPEMFile(t *testing.T) *os.File {
	t.Helper()

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
	require.NoError(t, err)

	err = pem.Encode(tmpfile, pemBlock)
	require.NoError(t, err)

	return tmpfile
}

func setupBenchmarkBundle(b *testing.B, fs afero.Fs, bundlePath string, fileSize, numFiles int) *Bundle {
	b.Helper()

	if err := fs.MkdirAll(bundlePath, 0755); err != nil {
		b.Fatalf("failed to create bundle directory: %v", err)
	}

	fileContent := make([]byte, fileSize)
	for i := range fileContent {
		fileContent[i] = 'A'
	}

	fileList := make([]string, numFiles)
	md5Hash := md5.New()

	for i := 0; i < numFiles; i++ {
		fileName := fmt.Sprintf("file%d.py", i)
		fileList[i] = fileName
		filePath := filepath.Join(bundlePath, fileName)

		if err := afero.WriteFile(fs, filePath, fileContent, 0644); err != nil {
			b.Fatalf("failed to write file %s: %v", fileName, err)
		}

		md5Hash.Write(fileContent)
	}

	checksum := fmt.Sprintf("%x", md5Hash.Sum(nil))

	if numFiles == 0 {
		checksum = "d41d8cd98f00b204e9800998ecf8427e"
	}

	return &Bundle{
		Name: "benchmark-bundle",
		Path: bundlePath,
		Spec: &APISpec{
			APIDefinition: &apidef.APIDefinition{
				CustomMiddlewareBundle: "benchmark-bundle.zip",
			},
		},
		Manifest: apidef.BundleManifest{
			Checksum: checksum,
			FileList: fileList,
		},
		Gw: &Gateway{},
	}
}

func BenchmarkBundle_Verify(b *testing.B) {
	benchmarks := []struct {
		name     string
		fileSize int
		numFiles int
	}{
		{"empty_file_list", 0, 0},
		{"single_small_file_1KB", 1024, 1},
		{"single_large_file_1MB", 1024 * 1024, 1},
		{"multiple_files_10x10KB", 10 * 1024, 10},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			// Setup bundle and filesystem
			fs := afero.NewMemMapFs()
			bundlePath := "/test/bundles/benchmark-bundle"
			bundle := setupBenchmarkBundle(b, fs, bundlePath, bm.fileSize, bm.numFiles)

			// Configure GW with no public key (no signature verification)
			bundle.Gw.SetConfig(config.Config{})

			// Initialize BundleChecksumVerifier
			bundle.Gw.BundleChecksumVerifier = defaultBundleVerifyFunction

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				err := bundle.PartialVerify(fs, false)
				assert.NoError(b, err)
			}
		})
	}
}
