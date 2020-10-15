package bundler

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/TykTechnologies/tyk/v3/apidef"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
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

func init() {
	testApp = kingpin.New("tyk-cli", "")
	AddTo(testApp)

	// Setup default values:
	bundlePath := defaultBundlePath
	bundler.bundlePath = &bundlePath
	manifestPath := defaultManifestPath
	bundler.manifestPath = &manifestPath
}

func writeManifestFile(t testing.TB, manifest interface{}, filename string) *string {
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

func TestCommands(t *testing.T) {
	defer os.Remove(defaultManifestPath)
	writeManifestFile(t, standardManifest, defaultManifestPath)
	_, err := testApp.Parse([]string{"bundle", "build", "-y"})
	if err != nil {
		t.Fatalf("Command not found")
	}
}
func TestBuild(t *testing.T) {
	defer os.Remove(defaultManifestPath)

	// Test for common errors first:
	t.Run("Bundle errors", func(t *testing.T) {
		ctx := &kingpin.ParseContext{}
		err := bundler.Build(ctx)
		if err != errManifestLoad {
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
		if err != errNoDriver {
			t.Fatal("Expected no driver error")
		}
		filename = writeManifestFile(t, &apidef.BundleManifest{
			FileList:         []string{},
			CustomMiddleware: apidef.MiddlewareSection{},
		}, defaultManifestPath)
		bundler.manifestPath = filename
		err = bundler.Build(ctx)
		if err != errNoHooks {
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
