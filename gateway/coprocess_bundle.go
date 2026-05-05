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

type bundleChecksumVerifyFunction func(bundle *Bundle, bundleFs afero.Fs) (sha256Hash hash.Hash, err error)

func defaultBundleVerifyFunction(b *Bundle, bundleFs afero.Fs) (sha256Hash hash.Hash, err error) {
	md5Hash := md5.New()
	sha256Hash = sha256.New()

	w := io.MultiWriter(sha256Hash, md5Hash)
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

	checksum := fmt.Sprintf("%x", md5Hash.Sum(nil))
	if checksum != b.Manifest.Checksum {
		return nil, errors.New("invalid checksum")
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
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("----> Verifying bundle: ", b.Spec.CustomMiddlewareBundle)
	hasKey := b.Gw.GetConfig().PublicKeyPath != ""
	hasSignature := b.Manifest.Signature != ""

	if hasKey && !hasSignature {
		return errors.New("Bundle isn't signed")
	}

	// check hash first then check signature
	sha256Hash, err := b.Gw.BundleChecksumVerifier(b, bundleFs)
	if err != nil {
		return err
	}
	if hasKey {
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

func (b *Bundle) PartialVerify(bundleFs afero.Fs, skipVerify bool) error {
	if skipVerify {
		return nil
	}

	hasKey := b.Gw.GetConfig().PublicKeyPath != ""
	hasSignature := b.Manifest.Signature != ""

	if !hasSignature {
		return nil
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("----> Verifying bundle: ", b.Spec.CustomMiddlewareBundle)
	// Make a single call to compute both hashes if needed
	sha256Hash, err := b.Gw.BundleChecksumVerifier(b, bundleFs)
	if err != nil {
		return err
	}

	if hasKey {
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

// FetchBundle fetches the API spec's CustomMiddlewareBundle. Preserved for
// backward compatibility; multi-bundle callers should use FetchBundleByName.
func (gw *Gateway) FetchBundle(bundleFs afero.Fs, spec *APISpec) (Bundle, error) {
	return gw.FetchBundleByName(bundleFs, spec, spec.CustomMiddlewareBundle)
}

// FetchBundleByName fetches a bundle by name (resolved against the gateway's
// BundleBaseURL). The returned Bundle.Name is set to bundleName so subsequent
// save/verify steps stay scoped to this specific bundle.
func (gw *Gateway) FetchBundleByName(bundleFs afero.Fs, spec *APISpec, bundleName string) (Bundle, error) {
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

	u.Path = path.Join(u.Path, bundleName)

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

	bundle.Name = bundleName
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

// loadBundleWithFs loads and validates one or more middleware bundles for the
// given API specification using the provided filesystem.
//
// Selection rule (backward compatible):
//   - If spec.CustomMiddlewareBundles is non-empty, every entry is fetched,
//     unpacked into its own subdirectory under the API's bundle root, and
//     its manifest merged into spec.CustomMiddleware.
//   - Otherwise, if spec.CustomMiddlewareBundle is set, the legacy
//     single-bundle path is used unchanged — same on-disk layout, same
//     AddToSpec replacement semantics. Existing deployments continue to
//     behave identically.
//
// Returns an error if any bundle cannot be fetched, saved, or verified.
func (gw *Gateway) loadBundleWithFs(spec *APISpec, bundleFs afero.Fs) error {
	if gw.GetConfig().ManagementNode {
		return nil
	}
	if spec.CustomMiddlewareBundleDisabled {
		return nil
	}

	bundleNames := spec.CustomMiddlewareBundles
	if len(bundleNames) == 0 && spec.CustomMiddlewareBundle != "" {
		// Legacy single-bundle path — preserve exactly to avoid changing
		// on-disk layout, hashing, or AddToSpec replacement semantics.
		return gw.loadSingleBundle(spec, bundleFs)
	}
	if len(bundleNames) == 0 {
		return nil
	}

	if gw.GetConfig().BundleBaseURL == "" {
		return bundleError(spec, nil, "No bundle base URL set, skipping bundle")
	}

	if spec.CustomMiddlewareBundle != "" {
		log.WithFields(logrus.Fields{
			"prefix": "main",
			"api_id": spec.APIID,
		}).Warning("Both custom_middleware_bundle and custom_middleware_bundles are set; the singular field is ignored.")
	}

	rootPath := gw.getBundleDestPath(spec)
	if err := bundleFs.MkdirAll(rootPath, 0700); err != nil {
		return bundleError(spec, err, "Couldn't create bundle root directory")
	}

	// Reset the spec's middleware section before merging — multi-bundle mode
	// is the source of truth for hooks, not whatever was previously attached.
	spec.CustomMiddleware = apidef.MiddlewareSection{}

	for _, name := range bundleNames {
		if name == "" {
			continue
		}
		if err := gw.loadOneBundleForMerge(spec, bundleFs, rootPath, name); err != nil {
			return err
		}
	}

	// Initialise non-goja drivers once after all bundles are merged. The legacy
	// single-bundle path does this inside Bundle.AddToSpec; for multi-bundle we
	// do it explicitly with the merged Driver.
	if dispatcher := loadedDrivers[spec.CustomMiddleware.Driver]; dispatcher != nil {
		dispatcher.HandleMiddlewareCache(&apidef.BundleManifest{
			CustomMiddleware: spec.CustomMiddleware,
		}, rootPath)
	}

	return nil
}

// loadSingleBundle is the original single-bundle path, factored out so the
// new multi-bundle entry point can fall back to it without behavioural
// drift. Existing single-bundle deployments take this path unchanged.
func (gw *Gateway) loadSingleBundle(spec *APISpec, bundleFs afero.Fs) error {
	if gw.GetConfig().BundleBaseURL == "" {
		return bundleError(spec, nil, "No bundle base URL set, skipping bundle")
	}

	destPath := gw.getBundleDestPath(spec)

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

// loadOneBundleForMerge fetches/loads a single bundle into a per-bundle
// subdirectory under rootPath, then merges its manifest into spec.CustomMiddleware
// with file paths rewritten so api_loader's prefix-join still resolves
// correctly.
func (gw *Gateway) loadOneBundleForMerge(spec *APISpec, bundleFs afero.Fs, rootPath, bundleName string) error {
	subdir := bundleSubdirName(bundleName)
	destPath := filepath.Join(rootPath, subdir)

	bundle := Bundle{
		Name: bundleName,
		Path: destPath,
		Spec: spec,
		Gw:   gw,
	}

	if _, err := bundleFs.Stat(destPath); err == nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("Loading existing bundle: ", bundleName)

		if err := loadBundleManifestNamed(bundleFs, &bundle, bundleName, true, gw.GetConfig().SkipVerifyExistingPluginBundle); err != nil {
			return bundleError(spec, err, fmt.Sprintf("Couldn't load bundle %q", bundleName))
		}
	} else {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("----> Fetching Bundle: ", bundleName)

		fetched, err := gw.FetchBundleByName(bundleFs, spec, bundleName)
		if err != nil {
			return bundleError(spec, err, fmt.Sprintf("Couldn't fetch bundle %q", bundleName))
		}

		if err := bundleFs.MkdirAll(destPath, 0700); err != nil {
			return bundleError(spec, err, fmt.Sprintf("Couldn't create bundle directory for %q", bundleName))
		}

		fetched.Path = destPath
		if err := saveBundle(bundleFs, &fetched, destPath, spec); err != nil {
			return bundleError(spec, err, fmt.Sprintf("Couldn't save bundle %q", bundleName))
		}

		bundle = fetched
		bundle.Path = destPath

		if err := loadBundleManifestNamed(bundleFs, &bundle, bundleName, false, false); err != nil {
			if removeErr := bundleFs.RemoveAll(bundle.Path); removeErr != nil {
				bundleError(spec, removeErr, "Couldn't remove bundle")
			}
			return bundleError(spec, err, fmt.Sprintf("Couldn't load bundle %q", bundleName))
		}
	}

	if err := mergeBundleManifest(spec, &bundle.Manifest, subdir, bundleName); err != nil {
		return bundleError(spec, err, fmt.Sprintf("Couldn't merge bundle %q", bundleName))
	}

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("----> Merged bundle into spec: ", bundleName)

	return nil
}

// loadBundleManifestNamed mirrors loadBundleManifest but uses the supplied
// bundleName for log messages so multi-bundle merges have meaningful logs.
// The verification logic is identical.
func loadBundleManifestNamed(bundleFs afero.Fs, bundle *Bundle, bundleName string, partial bool, skipVerification bool) error {
	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("----> Loading bundle: ", bundleName)

	manifestPath := filepath.Join(bundle.Path, "manifest.json")
	f, err := bundleFs.Open(manifestPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&bundle.Manifest); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Info("----> Couldn't unmarshal the manifest file for bundle: ", bundleName)
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
		}).Info("----> Bundle verification failed: ", bundleName)
		return err
	}

	return nil
}

// mergeBundleManifest merges a bundle's manifest into the spec's
// CustomMiddleware section. Each entry's Path is prepended with the bundle's
// subdir so the api_loader's prefix-join (prefix = api bundle root) resolves
// to the correct file under the per-bundle subdirectory.
//
// Hook arity rules:
//   - pre/post/post_key_auth/response: append in declaration order
//   - auth_check: at most one bundle may set this; merging a second is an error
//   - driver: must be uniform; mismatch is an error
func mergeBundleManifest(spec *APISpec, manifest *apidef.BundleManifest, subdir, bundleName string) error {
	src := manifest.CustomMiddleware

	// Driver consistency
	if src.Driver != "" {
		if spec.CustomMiddleware.Driver == "" {
			spec.CustomMiddleware.Driver = src.Driver
		} else if spec.CustomMiddleware.Driver != src.Driver {
			return fmt.Errorf("bundle %q declares driver %q but earlier bundles set %q", bundleName, src.Driver, spec.CustomMiddleware.Driver)
		}
	}

	rewritePath := func(md apidef.MiddlewareDefinition) apidef.MiddlewareDefinition {
		if md.Path != "" {
			md.Path = filepath.Join(subdir, md.Path)
		}
		return md
	}

	// auth_check is single-valued across the whole API
	if src.AuthCheck.Name != "" {
		if spec.CustomMiddleware.AuthCheck.Name != "" {
			return fmt.Errorf("bundle %q declares an auth_check hook but another bundle has already set one (%q)", bundleName, spec.CustomMiddleware.AuthCheck.Name)
		}
		spec.CustomMiddleware.AuthCheck = rewritePath(src.AuthCheck)
	}

	for _, md := range src.Pre {
		spec.CustomMiddleware.Pre = append(spec.CustomMiddleware.Pre, rewritePath(md))
	}
	for _, md := range src.Post {
		spec.CustomMiddleware.Post = append(spec.CustomMiddleware.Post, rewritePath(md))
	}
	for _, md := range src.PostKeyAuth {
		spec.CustomMiddleware.PostKeyAuth = append(spec.CustomMiddleware.PostKeyAuth, rewritePath(md))
	}
	for _, md := range src.Response {
		spec.CustomMiddleware.Response = append(spec.CustomMiddleware.Response, rewritePath(md))
	}

	// IdExtractor: take the first bundle that sets one
	if !spec.CustomMiddleware.IdExtractor.Disabled && spec.CustomMiddleware.IdExtractor.ExtractWith == "" && src.IdExtractor.ExtractWith != "" {
		spec.CustomMiddleware.IdExtractor = src.IdExtractor
	}

	return nil
}

// bundleSubdirName derives a filesystem-friendly subdirectory name from a
// bundle filename. The output is stable across runs and gateways so that an
// already-unpacked bundle can be reused without redownload.
func bundleSubdirName(bundleName string) string {
	clean := strings.TrimSuffix(bundleName, filepath.Ext(bundleName))
	clean = strings.ReplaceAll(clean, "/", "__")
	clean = strings.ReplaceAll(clean, "\\", "__")
	if clean == "" {
		// Fallback: hash the original name so we always produce *something*.
		sum := md5.Sum([]byte(bundleName))
		return fmt.Sprintf("bundle_%x", sum[:6])
	}
	return clean
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
