package bundler

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TykTechnologies/goverify"
	"github.com/TykTechnologies/tyk/apidef"

	kingpin "github.com/alecthomas/kingpin/v2"
)

var (
	testApp *kingpin.Application

	standardManifest = &apidef.BundleManifest{
		FileList: []string{},
		CustomMiddleware: apidef.MiddlewareSection{
			Pre: []apidef.MiddlewareDefinition{
				{
					Name: "MyPreHook",
				},
			},
			Driver: "python",
		},
	}
)

const testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----`

const testPublicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----`

// Verifies: SW-REQ-100
func TestMain(m *testing.M) {
	testApp = kingpin.New("tyk-cli", "")
	AddTo(testApp)

	// Setup default values:
	bundlePath := defaultBundlePath
	bundler.bundlePath = &bundlePath
	manifestPath := defaultManifestPath
	bundler.manifestPath = &manifestPath

	os.Exit(m.Run())
}

// Verifies: SW-REQ-100
func writeManifestFile(t testing.TB, manifest interface{}, filename string) *string {
	t.Helper()
	var data []byte
	var err error
	switch manifest.(type) {
	case *apidef.BundleManifest:
		data, err = json.Marshal(&manifest)
		if err != nil {
			t.Fatalf("Couldn't marshal manifest file: %s", err.Error())
		}
	case string:
		manifestString := manifest.(string)
		data = []byte(manifestString)
	}
	ioutil.WriteFile(filename, data, 0600)
	if err != nil {
		t.Fatalf("Couldn't write manifest file: %s", err.Error())
	}
	return &filename
}

// Verifies: STK-REQ-025, SYS-REQ-113, SW-REQ-100
// SYS-REQ-113:nominal:nominal
// SW-REQ-100:nominal:nominal
// SW-REQ-100:boundary:nominal
// MCDC SYS-REQ-113: plugin_bundle_operation_requested=F, plugin_bundle_result_determined=F => TRUE
// MCDC SYS-REQ-113: plugin_bundle_operation_requested=T, plugin_bundle_result_determined=T => TRUE
//
//mcdc:ignore SYS-REQ-113: plugin_bundle_operation_requested=T, plugin_bundle_result_determined=F => FALSE -- violation row is the negation of the plugin-bundle result guarantee; these tests assert requested bundle operations either register commands, produce bundles/signatures/checksums, or return explicit local errors [category: defensive] [reviewed: agent:codex]
func TestCommands(t *testing.T) {
	defer os.Remove(defaultManifestPath)
	writeManifestFile(t, standardManifest, defaultManifestPath)
	_, err := testApp.Parse([]string{"bundle", "build", "-y"})
	if err != nil {
		t.Fatalf("Command not found")
	}
}

// Verifies: STK-REQ-025, SYS-REQ-113, SW-REQ-100
// STK-REQ-025:STK-REQ-025-AC-01:acceptance
// STK-REQ-025:STK-REQ-025-AC-02:acceptance
// SW-REQ-100:nominal:nominal
// SW-REQ-100:boundary:nominal
// SW-REQ-100:error_handling:nominal
// SW-REQ-100:error_handling:negative
// STK-REQ-025:error_handling:negative
func TestBuild(t *testing.T) {
	defer os.Remove(defaultManifestPath)

	// Test for common errors first:
	t.Run("Bundle errors", func(t *testing.T) {
		ctx := &kingpin.ParseContext{}
		err := bundler.Build(ctx)
		if !errors.Is(err, errManifestLoad) {
			t.Fatalf("Expected manifest load error, got: %s", err.Error())
		}
		filename := writeManifestFile(t, "{", defaultManifestPath)
		bundler.manifestPath = filename
		err = bundler.Build(ctx)
		if !strings.Contains(err.Error(), "unexpected end of JSON input") {
			t.Fatalf("Expected JSON error, got: %s", err.Error())
		}
		filename = writeManifestFile(t, &apidef.BundleManifest{
			FileList: []string{},
			CustomMiddleware: apidef.MiddlewareSection{
				Pre: []apidef.MiddlewareDefinition{
					{
						Name: "MyPreHook",
					},
				},
			},
		}, defaultManifestPath)
		bundler.manifestPath = filename
		err = bundler.Build(ctx)
		if !errors.Is(err, errNoDriver) {
			t.Fatal("Expected no driver error")
		}
		filename = writeManifestFile(t, &apidef.BundleManifest{
			FileList:         []string{},
			CustomMiddleware: apidef.MiddlewareSection{},
		}, defaultManifestPath)
		bundler.manifestPath = filename
		err = bundler.Build(ctx)
		if !errors.Is(err, errNoHooks) {
			t.Fatal("Expected no hooks error")
		}
		filename = writeManifestFile(t, &apidef.BundleManifest{
			FileList: []string{
				"middleware.py",
			},
			CustomMiddleware: apidef.MiddlewareSection{
				Pre: []apidef.MiddlewareDefinition{
					{
						Name: "MyPreHook",
					},
				},
				Driver: "python",
			},
		}, defaultManifestPath)
		bundler.manifestPath = filename
		err = bundler.Build(ctx)
		if !strings.Contains(err.Error(), "nonexistent") {
			t.Fatalf("Expected nonexistent file error, got %s", err.Error())
		}
	})

	// Build a simple bundle:
	t.Run("Simple bundle build", func(t *testing.T) {
		ctx := &kingpin.ParseContext{}
		err := ioutil.WriteFile("middleware.py", []byte(""), 0600)
		if err != nil {
			t.Fatalf("Couldn't write middleware.py: %s", err.Error())
		}
		defer os.Remove("middleware.py")
		filename := writeManifestFile(t, &apidef.BundleManifest{
			FileList: []string{
				"middleware.py",
			},
			CustomMiddleware: apidef.MiddlewareSection{
				Pre: []apidef.MiddlewareDefinition{
					{
						Name: "MyPreHook",
					},
				},
				Driver: "python",
			},
		}, defaultManifestPath)
		bundler.manifestPath = filename
		skipSigning := true
		bundler.skipSigning = &skipSigning
		err = bundler.Build(ctx)
		zipFile, err := zip.OpenReader("bundle.zip")
		if err != nil {
			t.Fatalf("Couldn't initialize ZIP reader: %s\n", err.Error())
		}
		defer func() {
			zipFile.Close()
			os.Remove("bundle.zip")
		}()
		if len(zipFile.File) != 2 {
			t.Fatal("Number of bundled files doesn't match")
		}
		files := make(map[string][]byte)
		for _, f := range zipFile.File {
			reader, err := f.Open()
			defer reader.Close()
			if err != nil {
				t.Fatalf("Couldn't read from ZIP file: %s", err.Error())
			}
			if f.Name != defaultManifestPath && f.Name != "middleware.py" {
				t.Fatalf("Unexpected file: %s", f.Name)
			}
			var buf bytes.Buffer
			_, err = buf.ReadFrom(reader)
			if err != nil {
				t.Fatalf("Couldn't read from ZIP file: %s", err.Error())
			}
			files[defaultManifestPath] = buf.Bytes()
		}
		manifestData, ok := files[defaultManifestPath]
		if !ok {
			t.Fatalf("Couldn't found manifest data: %s", err.Error())
		}
		var manifest apidef.BundleManifest
		err = json.Unmarshal(manifestData, &manifest)
		if err != nil {
			t.Fatalf("Couldn't decode manifest data: %s", err.Error())
		}
		if manifest.Checksum != "d41d8cd98f00b204e9800998ecf8427e" {
			t.Fatalf("Bundle checksum doesn't match")
		}
		preHooks := manifest.CustomMiddleware.Pre
		if len(preHooks) != 1 {
			t.Fatalf("Bundle hooks doesn't match, got %d, expected 1", len(preHooks))
		}
		fileList := manifest.FileList
		if len(fileList) != 1 {
			t.Fatalf("Bundle file list doesn't match, got %d, expected 1", len(fileList))
		}
		if fileList[0] != "middleware.py" {
			t.Fatal("Bundle file 'middleware.py' wasn't found")
		}
		if manifest.CustomMiddleware.Driver != apidef.PythonDriver {
			t.Fatalf("Bundle driver doesn't match, got %s, expected %s", manifest.CustomMiddleware.Driver, apidef.PythonDriver)
		}
	})
}

// Verifies: STK-REQ-025, SYS-REQ-113, SW-REQ-100
// STK-REQ-025:STK-REQ-025-AC-03:acceptance
// SW-REQ-100:security:nominal
func TestBuildSignedBundleIncludesVerifiableSignature(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, defaultManifestPath)
	bundlePath := filepath.Join(dir, defaultBundlePath)
	middlewarePath := filepath.Join(dir, "middleware.py")
	keyPath := filepath.Join(dir, "private.pem")
	middlewareData := []byte("def middleware(request, session, metadata, spec):\n    return request, session, metadata\n")

	if err := ioutil.WriteFile(middlewarePath, middlewareData, 0600); err != nil {
		t.Fatalf("Couldn't write middleware file: %s", err.Error())
	}
	if err := ioutil.WriteFile(keyPath, []byte(testPrivateKey), 0600); err != nil {
		t.Fatalf("Couldn't write private key: %s", err.Error())
	}

	filename := writeManifestFile(t, &apidef.BundleManifest{
		FileList: []string{
			middlewarePath,
		},
		CustomMiddleware: apidef.MiddlewareSection{
			Pre: []apidef.MiddlewareDefinition{
				{
					Name: "MyPreHook",
				},
			},
			Driver: "python",
		},
	}, manifestPath)
	key := keyPath
	skipSigning := false
	prevManifestPath := bundler.manifestPath
	prevBundlePath := bundler.bundlePath
	prevKeyPath := bundler.keyPath
	prevSkipSigning := bundler.skipSigning
	bundler.manifestPath = filename
	bundler.bundlePath = &bundlePath
	bundler.keyPath = &key
	bundler.skipSigning = &skipSigning
	t.Cleanup(func() {
		bundler.manifestPath = prevManifestPath
		bundler.bundlePath = prevBundlePath
		bundler.keyPath = prevKeyPath
		bundler.skipSigning = prevSkipSigning
	})

	if err := bundler.Build(&kingpin.ParseContext{}); err != nil {
		t.Fatalf("Expected signed bundle to build, got: %s", err.Error())
	}

	manifest := readBundleManifest(t, bundlePath)
	if manifest.Signature == "" {
		t.Fatal("Expected bundle manifest signature to be populated")
	}
	signature, err := base64.StdEncoding.DecodeString(manifest.Signature)
	if err != nil {
		t.Fatalf("Expected bundle signature to be valid base64, got: %s", err.Error())
	}
	verifier, err := goverify.LoadPublicKeyFromString(testPublicKey)
	if err != nil {
		t.Fatalf("Couldn't load public key: %s", err.Error())
	}
	if err := verifier.Verify(middlewareData, signature); err != nil {
		t.Fatalf("Expected bundle signature to verify middleware bytes: %s", err.Error())
	}
}

// Verifies: SW-REQ-100
func readBundleManifest(t testing.TB, bundlePath string) apidef.BundleManifest {
	t.Helper()

	zipFile, err := zip.OpenReader(bundlePath)
	if err != nil {
		t.Fatalf("Couldn't initialize ZIP reader: %s", err.Error())
	}
	defer zipFile.Close()

	for _, f := range zipFile.File {
		if f.Name != defaultManifestPath {
			continue
		}
		reader, err := f.Open()
		if err != nil {
			t.Fatalf("Couldn't read manifest from ZIP file: %s", err.Error())
		}
		defer reader.Close()
		var buf bytes.Buffer
		if _, err = buf.ReadFrom(reader); err != nil {
			t.Fatalf("Couldn't read manifest data from ZIP file: %s", err.Error())
		}
		var manifest apidef.BundleManifest
		if err := json.Unmarshal(buf.Bytes(), &manifest); err != nil {
			t.Fatalf("Couldn't decode manifest data: %s", err.Error())
		}
		return manifest
	}

	t.Fatal("Couldn't find manifest data in bundle")
	return apidef.BundleManifest{}
}
