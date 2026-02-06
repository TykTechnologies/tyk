package gateway

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cenk/backoff"
	"github.com/spf13/afero"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/internal/sanitize"
)

var (
	bundleBackoffMultiplier float64 = 2
	bundleMaxBackoffRetries uint64  = 4
)

type bundleChecksumVerifyFunction func(bundle *Bundle, bundleFs afero.Fs, skipSignature, skipChecksum bool) (sha256Hash hash.Hash, err error)

func defaultBundleVerifyFunction(b *Bundle, bundleFs afero.Fs, skipSignature, skipChecksum bool) (sha256Hash hash.Hash, err error) {
	md5Hash := md5.New()
	sha256Hash = sha256.New()

	var writers []io.Writer
	if !skipSignature {
		writers = append(writers, sha256Hash)
	}
	if !skipChecksum {
		writers = append(writers, md5Hash)
	}

	if len(writers) == 0 {
		return sha256Hash, nil
	}

	w := io.MultiWriter(writers...)
	buf, ok := bundleVerifyPool.Get().(*[]byte)
	if !ok {
		return nil, errors.New("error verifying bundle, please try again")
	}
	defer bundleVerifyPool.Put(buf)

	for _, f := range b.Manifest.FileList {
		extractedPath := filepath.Join(b.Path, f)
		file, err := bundleFs.Open(extractedPath)
		if err != nil {
			return nil, err
		}
		_, err = io.CopyBuffer(w, file, *buf)
		file.Close()
		if err != nil {
			return nil, err
		}
	}

	if !skipChecksum {
		checksum := fmt.Sprintf("%x", md5Hash.Sum(nil))
		if checksum != b.Manifest.Checksum {
			return nil, errors.New("invalid checksum")
		}
		return sha256Hash, nil
	}

	return sha256Hash, nil
}

// Bundle is the basic bundle data structure, it holds the bundle name and the data.
type Bundle struct {
	Name     string
	Data     []byte
	Path     string
	Spec     *APISpec
	Manifest apidef.BundleManifest
	Gw       *Gateway `json:"-"`
}

var bundleVerifyPool = sync.Pool{
	New: func() interface{} {
		buffer := make([]byte, 32*1024)
		return &buffer
	},
}

func (b *Bundle) DeepVerify(bundleFs afero.Fs) error {
	hasKey := b.Gw.GetConfig().PublicKeyPath != ""
	hasSignature := b.Manifest.Signature != ""

	checkSignature := hasKey && hasSignature
	sha256Hash, err := b.Gw.BundleChecksumVerifier(b, bundleFs, !checkSignature, false)
	if err != nil {
		return err
	}
	if checkSignature {
		verifier, err := b.Gw.SignatureVerifier()
		if err != nil {
			return err
		}
		signed, err := base64.StdEncoding.DecodeString(b.Manifest.Signature)
		if err != nil {
			return err
		}
		if err := verifier.VerifyHash(sha256Hash.Sum(nil), signed); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bundle) PartialVerify(bundleFs afero.Fs, skipVerifyChecksum bool) error {
	hasKey := b.Gw.GetConfig().PublicKeyPath != ""
	if !hasKey {
		return nil
	}

	hasSignature := b.Manifest.Signature != ""
	if !hasSignature {
		return nil
	}

	sha256Hash, err := b.Gw.BundleChecksumVerifier(b, bundleFs, false, true)
	if err != nil {
		return err
	}

	verifier, err := b.Gw.SignatureVerifier()
	if err != nil {
		return err
	}
	signed, err := base64.StdEncoding.DecodeString(b.Manifest.Signature)
	if err != nil {
		return err
	}
	if err := verifier.VerifyHash(sha256Hash.Sum(nil), signed); err != nil {
		return err
	}

	if !skipVerifyChecksum {
		_, err = b.Gw.BundleChecksumVerifier(b, bundleFs, true, false)
		return err
	}
	return nil
}

//// Verify performs signature verification on the bundle file.
//func (b *Bundle) Verify(bundleFs afero.Fs) error {
//	log.WithFields(logrus.Fields{
//		"prefix": "main",
//	}).Info("----> Verifying bundle: ", b.Spec.CustomMiddlewareBundle)
//
//	var useSignature = b.Gw.GetConfig().PublicKeyPath != ""
//
//	var (
//		verifier goverify.Verifier
//		err      error
//	)
//
//	if useSignature {
//		// Perform signature verification if a public key path is set:
//		if b.Manifest.Signature == "" {
//			// Error: A public key is set, but the bundle isn't signed.
//			return errors.New("Bundle isn't signed")
//		}
//		verifier, err = b.Gw.SignatureVerifier()
//		if err != nil {
//			return err
//		}
//	}
//
//	sha256Hash, err := b.verifyChecksum(bundleFs, useSignature)
//	if err != nil {
//		return err
//	}
//
//	if useSignature {
//		signed, err := base64.StdEncoding.DecodeString(b.Manifest.Signature)
//		if err != nil {
//			return err
//		}
//		return verifier.VerifyHash(sha256Hash.Sum(nil), signed)
//	}
//	return nil
//}

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

// FileBundleGetter is a BundleGetter for testing.
type FileBundleGetter struct {
	Fs                 afero.Fs
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
		return nil, fmt.Errorf("Error getting bundle: %w", err)
	}

	if resp.StatusCode != 200 {
		httpError := fmt.Sprintf("HTTP Error, got status code %d", resp.StatusCode)
		return nil, errors.New(httpError)
	}

	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

// Get mocks an HTTP(S) GET request.
func (g *FileBundleGetter) Get() ([]byte, error) {
	return afero.ReadFile(g.Fs, strings.TrimPrefix(g.URL, "file://"))
}

// BundleSaver is an interface used by bundle saver structures.
type BundleSaver interface {
	Save(*Bundle, string, *APISpec) error
}

// ZipBundleSaver is a BundleSaver for ZIP files.
type ZipBundleSaver struct {
	Fs afero.Fs
}

// Save implements the main method of the BundleSaver interface. It makes use of archive/zip.
func (z *ZipBundleSaver) Save(bundle *Bundle, bundlePath string, _ *APISpec) error {
	buf := bytes.NewReader(bundle.Data)
	reader, err := zip.NewReader(buf, int64(len(bundle.Data)))
	if err != nil {
		return err
	}

	for _, f := range reader.File {
		if err := z.extractFile(f, bundlePath); err != nil {
			return err
		}
	}

	return nil
}

func (z *ZipBundleSaver) extractFile(f *zip.File, bundlePath string) error {
	if err := sanitize.ZipFilePath(f.Name, bundlePath); err != nil {
		return err
	}

	destPath := filepath.Join(bundlePath, f.Name)

	if f.FileHeader.Mode().IsDir() {
		return z.Fs.Mkdir(destPath, 0700)
	}

	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer func() {
		if err := rc.Close(); err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).WithError(err).Error("Couldn't close file")
		}
	}()

	newFile, err := z.Fs.Create(destPath)
	if err != nil {
		return err
	}

	defer func() {
		if err := newFile.Close(); err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).WithError(err).Error("Couldn't close file")
		}
	}()

	if _, err = io.Copy(newFile, rc); err != nil {
		return err
	}

	return nil
}

// FetchBundle will fetch a given bundle, using the right BundleGetter. The first argument is the bundle name, the base bundle URL will be used as prefix.
func (gw *Gateway) FetchBundle(bundleFs afero.Fs, spec *APISpec) (Bundle, error) {
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
	case "file":
		getter = &FileBundleGetter{
			Fs:                 bundleFs,
			URL:                bundleURL,
			InsecureSkipVerify: gw.GetConfig().BundleInsecureSkipVerify,
		}
	default:
		err = errors.New("Unknown URL scheme")
	}
	if err != nil {
		return bundle, err
	}

	bundleData, err := pullBundle(getter, bundleBackoffMultiplier)

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

	if bundleMaxBackoffRetries == 0 {
		err := downloadBundle()
		return bundleData, err
	}

	exponentialBackoff := backoff.NewExponentialBackOff()
	exponentialBackoff.Multiplier = backoffMultiplier
	exponentialBackoff.MaxInterval = 5 * time.Second
	err = backoff.Retry(downloadBundle, backoff.WithMaxRetries(exponentialBackoff, bundleMaxBackoffRetries))
	return bundleData, err
}

// saveBundle will save a bundle to the disk, see ZipBundleSaver methods for reference.
func saveBundle(bundleFs afero.Fs, bundle *Bundle, destPath string, spec *APISpec) error {
	bundleFormat := "zip"

	var bundleSaver BundleSaver

	// TODO: use enums?
	switch bundleFormat {
	case "zip":
		bundleSaver = &ZipBundleSaver{
			Fs: bundleFs,
		}
	}

	return bundleSaver.Save(bundle, destPath, spec)
}

// loadBundleManifest will parse the manifest file and return the bundle parameters.
func loadBundleManifest(bundleFs afero.Fs, bundle *Bundle, spec *APISpec, partial bool, skipVerification bool) error {
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("----> Loading bundle: ", spec.CustomMiddlewareBundle)

	manifestPath := filepath.Join(bundle.Path, "manifest.json")
	f, err := bundleFs.Open(manifestPath)
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

	if partial {
		err = bundle.PartialVerify(bundleFs, skipVerification)
	} else {
		err = bundle.DeepVerify(bundleFs)
	}
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("----> Bundle verification failed: ", spec.CustomMiddlewareBundle)
		return err
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

// loadBundle configures the gateway to load a custom middleware bundle based on the provided API specification.
// It verifies the existence, integrity, and configuration of the bundle, applying it to the spec if validation succeeds.
// Returns an error if the bundle cannot be loaded, validated, or is disabled in the spec.
func (gw *Gateway) loadBundle(spec *APISpec) error {
	return gw.loadBundleWithFs(spec, afero.NewOsFs())
}

// loadBundleWithFs loads and validates a middleware bundle for the given API specification using the provided filesystem.
// It operates only if required settings like CustomMiddlewareBundle and BundleBaseURL are configured in the API spec.
// The method handles bundle fetching, saving, and manifest validation.
// Returns an error if the bundle cannot be fetched, saved, or its manifest cannot be verified successfully.
func (gw *Gateway) loadBundleWithFs(spec *APISpec, bundleFs afero.Fs) error {
	if gw.GetConfig().ManagementNode {
		return nil
	}

	// Skip if no custom middleware bundle name is set.
	if spec.CustomMiddlewareBundleDisabled || spec.CustomMiddlewareBundle == "" {
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
	if _, err := bundleFs.Stat(destPath); err == nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Loading existing bundle: ", spec.CustomMiddlewareBundle)

		bundle := Bundle{
			Name: spec.CustomMiddlewareBundle,
			Path: destPath,
			Spec: spec,
			Gw:   gw,
		}

		err = loadBundleManifest(bundleFs, &bundle, spec, true, gw.GetConfig().SkipVerifyExistingPluginBundle)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "main",
			}).Info("----> Couldn't load bundle: ", spec.CustomMiddlewareBundle, " ", err)
			return err
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

	bundle, err := gw.FetchBundle(bundleFs, spec)
	if err != nil {
		return bundleError(spec, err, "Couldn't fetch bundle")
	}

	if err := bundleFs.MkdirAll(destPath, 0700); err != nil {
		return bundleError(spec, err, "Couldn't create bundle directory")
	}

	if err := saveBundle(bundleFs, &bundle, destPath, spec); err != nil {
		return bundleError(spec, err, "Couldn't save bundle")
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Debug("----> Saving Bundle: ", spec.CustomMiddlewareBundle)

	// Set the destination path:
	bundle.Path = destPath

	if err := loadBundleManifest(bundleFs, &bundle, spec, false, false); err != nil {
		bundleError(spec, err, "Couldn't load bundle")

		if removeErr := bundleFs.RemoveAll(bundle.Path); removeErr != nil {
			bundleError(spec, removeErr, "Couldn't remove bundle")
		}
		return err
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
