package main

import (
	"github.com/TykTechnologies/logrus"
	"github.com/TykTechnologies/goverify"
	"github.com/TykTechnologies/tykcommon"

	"archive/zip"
	"bytes"
	"crypto/md5"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

var tykBundlePath string

func init() {
	tykBundlePath = filepath.Join(config.MiddlewarePath, "middleware/bundles")
}

// Bundle is the basic bundle data structure, it holds the bundle name and the data.
type Bundle struct {
	Name     string
	Data     []byte
	Path     string
	Spec     *APISpec
	Manifest tykcommon.BundleManifest
}

func (b *Bundle) Verify() (err error) {
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("----> Verifying bundle: ", b.Spec.CustomMiddlewareBundle)

	var useSignature bool
	var bundleVerifier goverify.Verifier

	// Perform signature verification if a public key path is set:
	if config.PublicKeyPath != "" {
		if b.Manifest.Signature == "" {
			// Error: A public key is set, but the bundle isn't signed.
			err = errors.New("Bundle isn't signed")
		}
		if notificationVerifier == nil {
			bundleVerifier, err = goverify.LoadPublicKeyFromFile(config.PublicKeyPath)
		}

		if err != nil {
			return err
		}

		useSignature = true
	}

	h := md5.New()
	h.Write(b.Data)
	checksum := hex.EncodeToString(h.Sum(nil))

	var bundleData bytes.Buffer

	for _, f := range b.Manifest.FileList {
		extractedFilePath := filepath.Join(b.Path, f)

		var data []byte
		data, err = ioutil.ReadFile(extractedFilePath)
		if err != nil {
			break
		}

		bundleData.Write(data)
	}

	checksum = fmt.Sprintf("%x", md5.Sum(bundleData.Bytes()))

	if checksum != b.Manifest.Checksum {
		err = errors.New("Invalid checksum")
	}

	if useSignature {
		var signed []byte
		signed, err = b64.StdEncoding.DecodeString(b.Manifest.Signature)
		if err != nil {
			return err
		}
		err = bundleVerifier.Verify([]byte(bundleData.Bytes()), signed)
		if err != nil {
			return err
		}

	}

	return err
}

func (b *Bundle) AddToSpec() {
	b.Spec.APIDefinition.CustomMiddleware = b.Manifest.CustomMiddleware

	if GlobalDispatcher != nil {
		GlobalDispatcher.HandleMiddlewareCache(&b.Manifest, b.Path)
	}
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

	if !config.EnableBundleDownloader {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Warning("Bundle downloader is disabled.")
		err = errors.New("Bundle downloader is disabled.")
		return thisBundle, err
	}

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

	manifestPath := filepath.Join(bundle.Path, "manifest.json")
	var manifestData []byte
	manifestData, err = ioutil.ReadFile(manifestPath)

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
		bundleError(spec, err, "No bundle base URL set, skipping bundle")
		return
	}

	// Skip if the bundle destination path already exists.
	bundlePath := strings.Join([]string{spec.APIID, spec.CustomMiddlewareBundle}, "-")
	destPath := filepath.Join(tykBundlePath, bundlePath)

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
			}).Info("----> Couldn't load bundle: ", spec.CustomMiddlewareBundle, " ", err)
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
		bundleError(spec, err, "Couldn't fetch bundle")
		return
	}

	err = os.Mkdir(destPath, 0755)

	if err != nil {
		bundleError(spec, err, "Couldn't create bundle directory")
		return
	}

	err = saveBundle(&bundle, destPath, spec)

	if err != nil {
		bundleError(spec, err, "Couldn't save bundle")
		return
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Debug("----> Saving Bundle: ", spec.CustomMiddlewareBundle)

	// Set the destination path:
	bundle.Path = destPath

	err = loadBundleManifest(&bundle, spec, false)

	if err != nil {
		bundleError(spec, err, "Couldn't load bundle")

		removeErr := os.RemoveAll(bundle.Path)
		if removeErr != nil {
			bundleError(spec, err, "Couldn't remove bundle")
		}
		return
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("----> Bundle is valid, adding to spec: ", spec.CustomMiddlewareBundle)

	bundle.AddToSpec()

}

// bundleError is a log helper.
func bundleError(spec *APISpec, err error, message string) {
	log.WithFields(logrus.Fields{
		"prefix":      "main",
		"user_ip":     "-",
		"server_name": spec.APIDefinition.Proxy.TargetURL,
		"user_id":     "-",
		"org_id":      spec.APIDefinition.OrgID,
		"api_id":      spec.APIDefinition.APIID,
		"path":        "-",
	}).Error(message, ": ", err)
}

// getBundlePaths will return an array of the available bundle directories:
func getBundlePaths() []string {
	directories := make([]string, 0)
	bundles, _ := ioutil.ReadDir(tykBundlePath)
	for _, f := range bundles {
		if f.IsDir() {
			fullPath := filepath.Join(tykBundlePath, f.Name())
			directories = append(directories, fullPath)
		}
	}
	return directories
}
