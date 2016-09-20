package main

import (
	"github.com/Sirupsen/logrus"

	"archive/zip"
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Bundle is the basic bundle data structure, it holds the bundle name and the data.
type Bundle struct {
	Name string
	Data []byte
	Path string
}

// BundleGetter is used for downloading bundle data, see HttpBundleGetter for reference.
type BundleGetter interface {
	Get() ([]byte, error)
}

// HttpBundleGetter is a simple HTTP BundleGetter.
type HttpBundleGetter struct {
	Url string
}

// Get performs an HTTP GET request.
func (g *HttpBundleGetter) Get() (bundleData []byte, err error) {
	log.Println("Calling HttpBundleGetter", g.Url)
	// bundleData = []byte("hello")

	var resp *http.Response

	resp, err = http.Get(g.Url)

	if err != nil {
		log.Println("err", err)
		return nil, err
	}

	if resp.StatusCode != 200 {
		log.Println("err", resp.Status, resp.StatusCode)
		return nil, errors.New("HTTP Error")
	}

	defer resp.Body.Close()
	bundleData, err = ioutil.ReadAll(resp.Body)
	return bundleData, err
}

// BundleSaver is an interface used by bundle saver structures.
type BundleSaver interface {
	Save(*Bundle, string, *APISpec) error
}

// ZipBundleSaver is a BundleSaver for ZIP files.
type ZipBundleSaver struct {
}

// Save implements the main method of the BundleSaver interface. It makes use of archive/zip.
func (s *ZipBundleSaver) Save(bundle *Bundle, bundlePath string, spec *APISpec) (err error) {
	buf := bytes.NewReader(bundle.Data)
	reader, _ := zip.NewReader(buf, int64(len(bundle.Data)))

	for _, f := range reader.File {
		var rc io.ReadCloser
		rc, err = f.Open()

		if err != nil {
			return err
		}

		var destPath string
		destPath = filepath.Join(bundlePath, f.Name)

		isDir := f.FileHeader.Mode().IsDir()

		if isDir {
			err = os.Mkdir(destPath, 0755)
			if err != nil {
				return err
			}
		} else {
			var newFile *os.File
			newFile, err = os.Create(destPath)
			if err != nil {
				return err
			}
			_, err = io.Copy(newFile, rc)
			if err != nil {
				return err
			}
		}
	}
	return err
}

// fetchBundle will fetch a given bundle, using the right BundleGetter. The first argument is the bundle name, the base bundle URL will be used as prefix.
func fetchBundle(name string) (thisBundle Bundle, err error) {
	var bundleUrl string

	bundleUrl = strings.Join([]string{config.BundleBaseURL, name}, "")

	var thisGetter BundleGetter

	var u *url.URL
	u, err = url.Parse(bundleUrl)

	switch u.Scheme {
	case "http":
		thisGetter = &HttpBundleGetter{
			Url: bundleUrl,
		}
	default:
		err = errors.New("Unknown URL scheme!")
	}

	bundleData, err := thisGetter.Get()

	thisBundle = Bundle{
		Name: name,
		Data: bundleData,
	}

	return thisBundle, err
}

// saveBundle will save a bundle to the disk, see ZipBundleSaver methods for reference.
func saveBundle(bundle *Bundle, destPath string, spec *APISpec) (err error) {
	log.Println("saveBundle:", bundle, ", to: ", destPath)

	var bundleFormat = "zip"

	var bundleSaver BundleSaver

	// TODO: use enums?
	switch bundleFormat {
	case "zip":
		bundleSaver = &ZipBundleSaver{}
	}

	bundleSaver.Save(bundle, destPath, spec)

	return err
}

func loadManifest(bundle *Bundle, spec *APISpec) {
	log.Println("loadManifest: ", bundle, ", destPath: ", ", spec: ", spec)
	manifestPath := filepath.Join(bundle.Path, "manifest.json")
	log.Println("loadManifest, manifestPath: ", manifestPath)
}

// loadBundle wraps the load and save steps, it will return if an error occurs at any point.
func loadBundle(spec *APISpec) {
	var err error

	// Skip if no custom middleware bundle name is set.
	if spec.CustomMiddlewareBundle == "" {
		return
	}

  // Skip if no bundle base URL is set.
	if config.BundleBaseURL == "" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Error("An API specifies a custom middleware bundle, but no bundle base URL is set in your tyk.conf! Skipping bundle: ", spec.CustomMiddlewareBundle)
		return
	}

	// Skip if the bundle destination path already exists.
	bundlePath := strings.Join([]string{spec.APIID, spec.CustomMiddlewareBundle}, "-")
	log.Println("bundlePath =", bundlePath)
	destPath := filepath.Join("/Users/matias/dev/tyk", "middleware/bundles", bundlePath)
	log.Println("destPath =", destPath)

	if _, err := os.Stat(destPath); err == nil {
		log.Println("destPath exists!")
		return
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("----> Loading Bundle: ", spec.CustomMiddlewareBundle)

	var bundle Bundle
	bundle, err = fetchBundle(spec.CustomMiddlewareBundle)

	log.Println("bundle, err", bundle, err)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Error("----> Error when loading bundle: ", spec.CustomMiddlewareBundle, ", ", err)
		return
	}

	log.Println("destPath doesn't exist, save!", destPath)

	err = os.Mkdir(destPath, 0755)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Error("----> Error when creating bundle directory: ", spec.CustomMiddlewareBundle, ", ", err)
		// return
	}

	log.Println("destPath created", destPath)

	err = saveBundle(&bundle, destPath, spec)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Error("----> Error when saving bundle: ", spec.CustomMiddlewareBundle, ", ", err)
		return
	}

	// Set the destination path:
	bundle.Path = destPath

	// Load the manifest settings:
	loadManifest(&bundle, spec)

}
