package gateway

import (
	"path"
	"time"

	"github.com/cenk/backoff"

	"github.com/sirupsen/logrus"

	"archive/zip"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/TykTechnologies/goverify"
	"github.com/TykTechnologies/tyk/apidef"
)

const BackoffMultiplier = 2
const MaxBackoffRetries = 4

// Bundle is the basic bundle data structure, it holds the bundle name and the data.
type Bundle struct {
	Name     string
	Data     []byte
	Path     string
	Spec     *APISpec
	Manifest apidef.BundleManifest
	Gw       *Gateway `json:"-"`
}

// Verify performs a signature verification on the bundle file.
func (b *Bundle) Verify() error {
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("----> Verifying bundle: ", b.Spec.CustomMiddlewareBundle)

	var useSignature bool
	var bundleVerifier goverify.Verifier

	// Perform signature verification if a public key path is set:
	if b.Gw.GetConfig().PublicKeyPath != "" {
		if b.Manifest.Signature == "" {
			// Error: A public key is set, but the bundle isn't signed.
			return errors.New("Bundle isn't signed")
		}
		if b.Gw.NotificationVerifier == nil {
			var err error
			bundleVerifier, err = goverify.LoadPublicKeyFromFile(b.Gw.GetConfig().PublicKeyPath)
			if err != nil {
				return err
			}
		}

		useSignature = true
	}

	var bundleData bytes.Buffer

	for _, f := range b.Manifest.FileList {
		extractedPath := filepath.Join(b.Path, f)

		f, err := os.Open(extractedPath)
		if err != nil {
			return err
		}
		_, err = io.Copy(&bundleData, f)
		f.Close()
		if err != nil {
			return err
		}
	}

	checksum := fmt.Sprintf("%x", md5.Sum(bundleData.Bytes()))

	if checksum != b.Manifest.Checksum {
		return errors.New("Invalid checksum")
	}

	if useSignature {
		signed, err := base64.StdEncoding.DecodeString(b.Manifest.Signature)
		if err != nil {
			return err
		}
		if err := bundleVerifier.Verify(bundleData.Bytes(), signed); err != nil {
			return err
		}

	}

	return nil
}

// AddToSpec attaches the custom middleware settings to an API definition.
func (b *Bundle) AddToSpec() {
	b.Spec.CustomMiddleware = b.Manifest.CustomMiddleware

	// Load Python interpreter if the
	if loadedDrivers[b.Spec.CustomMiddleware.Driver] == nil && b.Spec.CustomMiddleware.Driver == apidef.PythonDriver {
		var err error
		loadedDrivers[apidef.PythonDriver], err = NewPythonDispatcher(b.Gw.GetConfig())
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "coprocess",
			}).WithError(err).Error("Couldn't load Python dispatcher")
			return
		}
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Info("Python dispatcher was initialized")
	}
	dispatcher := loadedDrivers[b.Spec.CustomMiddleware.Driver]
	if dispatcher != nil {
		dispatcher.HandleMiddlewareCache(&b.Manifest, b.Path)
	}
}

// BundleGetter is used for downloading bundle data, see HttpBundleGetter for reference.
type BundleGetter interface {
	Get() ([]byte, error)
}

// HTTPBundleGetter is a simple HTTP BundleGetter.
type HTTPBundleGetter struct {
	URL                string
	InsecureSkipVerify bool
}

// MockBundleGetter is a BundleGetter for testing.
type MockBundleGetter struct {
	URL                string
	InsecureSkipVerify bool
}

// Get performs an HTTP GET request.
func (g *HTTPBundleGetter) Get() ([]byte, error) {
	tr := &(*http.DefaultTransport.(*http.Transport))
	tr.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: g.InsecureSkipVerify,
		MaxVersion:         tls.VersionTLS12,
	}
	client := &http.Client{Transport: tr}
	client.Timeout = 5 * time.Second

	log.Infof("Attempting to download plugin bundle: %v", g.URL)
	resp, err := client.Get(g.URL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		httpError := fmt.Sprintf("HTTP Error, got status code %d", resp.StatusCode)
		return nil, errors.New(httpError)
	}

	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

// Get mocks an HTTP(S) GET request.
func (g *MockBundleGetter) Get() ([]byte, error) {
	if g.InsecureSkipVerify {
		return []byte("bundle-insecure"), nil
	}
	return []byte("bundle"), nil
}

// BundleSaver is an interface used by bundle saver structures.
type BundleSaver interface {
	Save(*Bundle, string, *APISpec) error
}

// ZipBundleSaver is a BundleSaver for ZIP files.
type ZipBundleSaver struct{}

// Save implements the main method of the BundleSaver interface. It makes use of archive/zip.
func (ZipBundleSaver) Save(bundle *Bundle, bundlePath string, spec *APISpec) error {
	buf := bytes.NewReader(bundle.Data)
	reader, err := zip.NewReader(buf, int64(len(bundle.Data)))
	if err != nil {
		return err
	}

	for _, f := range reader.File {
		destPath := filepath.Join(bundlePath, f.Name)

		if f.FileHeader.Mode().IsDir() {
			if err := os.Mkdir(destPath, 0700); err != nil {
				return err
			}
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		newFile, err := os.Create(destPath)
		if err != nil {
			return err
		}
		if _, err = io.Copy(newFile, rc); err != nil {
			return err
		}
		rc.Close()
		if err := newFile.Close(); err != nil {
			return err
		}
	}
	return nil
}

// fetchBundle will fetch a given bundle, using the right BundleGetter. The first argument is the bundle name, the base bundle URL will be used as prefix.
func (gw *Gateway) fetchBundle(spec *APISpec) (Bundle, error) {
	bundle := Bundle{Gw: gw}
	var err error

	if !gw.GetConfig().EnableBundleDownloader {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Warning("Bundle downloader is disabled.")
		err = errors.New("Bundle downloader is disabled")
		return bundle, err
	}

	u, err := url.Parse(gw.GetConfig().BundleBaseURL)
	if err != nil {
		return bundle, err
	}

	u.Path = path.Join(u.Path, spec.CustomMiddlewareBundle)

	bundleURL := u.String()

	var getter BundleGetter

	switch u.Scheme {
	case "http":
		getter = &HTTPBundleGetter{
			URL:                bundleURL,
			InsecureSkipVerify: false,
		}
	case "https":
		getter = &HTTPBundleGetter{
			URL:                bundleURL,
			InsecureSkipVerify: gw.GetConfig().BundleInsecureSkipVerify,
		}
	case "mock":
		getter = &MockBundleGetter{
			URL:                bundleURL,
			InsecureSkipVerify: gw.GetConfig().BundleInsecureSkipVerify,
		}
	default:
		err = errors.New("Unknown URL scheme")
	}
	if err != nil {
		return bundle, err
	}

	bundleData, err := pullBundle(getter, BackoffMultiplier)

	bundle.Name = spec.CustomMiddlewareBundle
	bundle.Data = bundleData
	bundle.Spec = spec
	return bundle, err
}

func pullBundle(getter BundleGetter, backoffMultiplier float64) ([]byte, error) {
	var bundleData []byte
	var err error
	downloadBundle := func() error {
		bundleData, err = getter.Get()
		return err
	}

	exponentialBackoff := backoff.NewExponentialBackOff()
	exponentialBackoff.Multiplier = backoffMultiplier
	exponentialBackoff.MaxInterval = 5 * time.Second
	err = backoff.Retry(downloadBundle, backoff.WithMaxRetries(exponentialBackoff, MaxBackoffRetries))
	return bundleData, err
}

// saveBundle will save a bundle to the disk, see ZipBundleSaver methods for reference.
func saveBundle(bundle *Bundle, destPath string, spec *APISpec) error {
	bundleFormat := "zip"

	var bundleSaver BundleSaver

	// TODO: use enums?
	switch bundleFormat {
	case "zip":
		bundleSaver = ZipBundleSaver{}
	}
	bundleSaver.Save(bundle, destPath, spec)

	return nil
}

// loadBundleManifest will parse the manifest file and return the bundle parameters.
func loadBundleManifest(bundle *Bundle, spec *APISpec, skipVerification bool) error {
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("----> Loading bundle: ", spec.CustomMiddlewareBundle)

	manifestPath := filepath.Join(bundle.Path, "manifest.json")
	f, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&bundle.Manifest); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("----> Couldn't unmarshal the manifest file for bundle: ", spec.CustomMiddlewareBundle)
		return err
	}

	if skipVerification {
		return nil
	}

	if err := bundle.Verify(); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("----> Bundle verification failed: ", spec.CustomMiddlewareBundle)
	}
	return nil
}

func (gw *Gateway) getBundleDestPath(spec *APISpec) string {
	tykBundlePath := filepath.Join(gw.GetConfig().MiddlewarePath, "bundles")
	bundlePath, _ := gw.getHashedBundleName(spec.CustomMiddlewareBundle)
	return filepath.Join(tykBundlePath, bundlePath)
}

func (gw *Gateway) getHashedBundleName(bundleName string) (string, error) {
	bundleNameHash := md5.New()
	_, err := io.WriteString(bundleNameHash, bundleName)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", bundleNameHash.Sum(nil)), nil
}

// loadBundle wraps the load and save steps, it will return if an error occurs at any point.
func (gw *Gateway) loadBundle(spec *APISpec) error {
	// Skip if no custom middleware bundle name is set.
	if spec.CustomMiddlewareBundle == "" {
		return nil
	}

	// Skip if no bundle base URL is set.
	if gw.GetConfig().BundleBaseURL == "" {
		return bundleError(spec, nil, "No bundle base URL set, skipping bundle")
	}

	// get bundle destination on disk
	destPath := gw.getBundleDestPath(spec)

	// Skip if the bundle destination path already exists.
	// The bundle exists, load and return:
	if _, err := os.Stat(destPath); err == nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Loading existing bundle: ", spec.CustomMiddlewareBundle)

		bundle := Bundle{
			Name: spec.CustomMiddlewareBundle,
			Path: destPath,
			Spec: spec,
			Gw:   gw,
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

		return nil
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("----> Fetching Bundle: ", spec.CustomMiddlewareBundle)

	bundle, err := gw.fetchBundle(spec)
	if err != nil {
		return bundleError(spec, err, "Couldn't fetch bundle")
	}

	if err := os.MkdirAll(destPath, 0700); err != nil {
		return bundleError(spec, err, "Couldn't create bundle directory")
	}

	if err := saveBundle(&bundle, destPath, spec); err != nil {
		return bundleError(spec, err, "Couldn't save bundle")
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Debug("----> Saving Bundle: ", spec.CustomMiddlewareBundle)

	// Set the destination path:
	bundle.Path = destPath

	if err := loadBundleManifest(&bundle, spec, false); err != nil {
		bundleError(spec, err, "Couldn't load bundle")

		if err := os.RemoveAll(bundle.Path); err != nil {
			bundleError(spec, err, "Couldn't remove bundle")
		}
		return nil
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("----> Bundle is valid, adding to spec: ", spec.CustomMiddlewareBundle)

	bundle.AddToSpec()

	return nil
}

// bundleError is a log helper.
func bundleError(spec *APISpec, err error, message string) error {
	if err != nil {
		message = fmt.Sprintf("%s: %s", message, err.Error())
	}
	log.WithFields(logrus.Fields{
		"prefix":      "main",
		"user_ip":     "-",
		"server_name": spec.Proxy.TargetURL,
		"user_id":     "-",
		"org_id":      spec.OrgID,
		"api_id":      spec.APIID,
		"path":        "-",
	}).Error(message)
	return errors.New(message)
}
