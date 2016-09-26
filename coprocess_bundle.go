package main

import (
	"github.com/Sirupsen/logrus"
	"github.com/TykTechnologies/tykcommon"

	"crypto/md5"
	"io"
	"encoding/hex"
	"encoding/json"
	"archive/zip"
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"fmt"
)

// Bundle is the basic bundle data structure, it holds the bundle name and the data.
type Bundle struct {
	Name string
	Data []byte
	Path string
	Spec *APISpec
	Manifest tykcommon.BundleManifest
}

func(b *Bundle) Verify() (err error) {
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("----> Verifying bundle: ", b.Spec.CustomMiddlewareBundle)

	h := md5.New()
	h.Write(b.Data)
	checksum := hex.EncodeToString(h.Sum(nil))

	var bundleChecksums []string

	for _, f := range b.Manifest.FileList {
		extractedFilePath := filepath.Join(b.Path, f)

		var data []byte
		data, err = ioutil.ReadFile(extractedFilePath)
		if err != nil {
			break
		}
		hash := fmt.Sprintf("%x", md5.Sum(data))
		bundleChecksums = append(bundleChecksums, hash)
	}

	mergedChecksums := strings.Join(bundleChecksums, "")
	checksum = fmt.Sprintf("%x", md5.Sum([]byte(mergedChecksums)))

	if checksum != b.Manifest.Checksum {
		err = errors.New("Invalid checksum")
	}

	return err
}

func(b *Bundle) AddToSpec() {
	b.Spec.APIDefinition.CustomMiddleware = b.Manifest.CustomMiddleware
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
	var resp *http.Response

	resp, err = http.Get(g.Url)

	if err != nil {
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
func fetchBundle(spec *APISpec) (thisBundle Bundle, err error) {
	var bundleUrl string

	bundleUrl = strings.Join([]string{config.BundleBaseURL, spec.CustomMiddlewareBundle}, "")

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
		Name: spec.CustomMiddlewareBundle,
		Data: bundleData,
		Spec: spec,
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


// loadBundleManifest will parse the manifest file and return the bundle parameters.
func loadBundleManifest(bundle *Bundle, spec *APISpec, skipVerification bool) (err error) {
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("----> Loading bundle: ", spec.CustomMiddlewareBundle)

	log.Println("loadManifest: ", bundle, ", destPath: ", ", spec: ", spec)
	manifestPath := filepath.Join(bundle.Path, "manifest.json")
	log.Println("loadManifest, manifestPath: ", manifestPath)
	var manifestData []byte
	manifestData, err = ioutil.ReadFile(manifestPath)

	// var manifest tykcommon.BundleManifest
	err = json.Unmarshal(manifestData, &bundle.Manifest)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("----> Couldn't unmarshal the manifest file for bundle: ", spec.CustomMiddlewareBundle)
		return err
	}

	if skipVerification {
		return err
	}

	err = bundle.Verify()
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("----> Bundle verification failed: ", spec.CustomMiddlewareBundle)
	}

	return err
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

	// The bundle exists, load and return:
	if _, err := os.Stat(destPath); err == nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Loading existing bundle: ", spec.CustomMiddlewareBundle)

		bundle := Bundle{
			Name: spec.CustomMiddlewareBundle,
			Path: destPath,
			Spec: spec,
		}

		err = loadBundleManifest(&bundle, spec, true)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Info("----> Couldn't load bundle: ", spec.CustomMiddlewareBundle, err)
		}

		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("----> Using bundle: ", spec.CustomMiddlewareBundle)

		bundle.AddToSpec()

		return
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("----> Fetching Bundle: ", spec.CustomMiddlewareBundle)

	var bundle Bundle
	bundle, err = fetchBundle(spec)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Error("----> Couldn't fetch bundle: ", spec.CustomMiddlewareBundle, ", ", err)
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

	err = saveBundle(&bundle, destPath, spec)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Error("----> Couldn't save bundle: ", spec.CustomMiddlewareBundle, ", ", err)
		return
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Debug("----> Saving Bundle: ", spec.CustomMiddlewareBundle)

	// Set the destination path:
	bundle.Path = destPath

	err = loadBundleManifest(&bundle, spec, false)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("----> Couldn't load bundle: ", spec.CustomMiddlewareBundle, err)
		return
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("----> Bundle is valid, adding to spec: ", spec.CustomMiddlewareBundle)

	bundle.AddToSpec()

}
