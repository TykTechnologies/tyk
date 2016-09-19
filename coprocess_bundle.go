package main

import(
  "github.com/Sirupsen/logrus"

  "errors"
  "strings"
  "net/http"
  "net/url"
  "io"
  "io/ioutil"
  "path/filepath"
  "archive/zip"
  "bytes"
  "os"
)

const(
  baseBundleUrl = "http://127.0.0.1/dev/"
)

// Bundle is the basic bundle data structure, it holds the bundle name and the data.
type Bundle struct {
  Name string
  Data []byte
}

// BundleGetter is used for downloading bundle data, check HttpBundleGetter for reference.
type BundleGetter interface {
  Get() ([]byte, error)
}

// HttpBundleGetter is a simple HTTP BundleGetter.
type HttpBundleGetter struct {
  Url string
}

func(g *HttpBundleGetter) Get() (bundleData []byte, err error) {
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


type BundleSaver interface {
  Save(*Bundle, string, *APISpec) (error)
}

type BaseBundleSaver struct {}

type ZipBundleSaver struct {
}

func(s *ZipBundleSaver) Save(bundle *Bundle, destPath string, spec *APISpec) (err error) {
  buf := bytes.NewReader(bundle.Data)
  reader, _ := zip.NewReader(buf, int64(len(bundle.Data)))

  for _, f := range reader.File {
    log.Println("*** File: ", f.Name)
    var rc io.ReadCloser
    rc, err = f.Open()
    if err != nil {
      return err
    }
    // _, err = io.Copy()
  }

  log.Println("zipreader =", reader)
  return err
}

func fetchBundle(name string) (thisBundle Bundle, err error) {
  var bundleUrl string

  bundleUrl = strings.Join([]string{baseBundleUrl, name}, "")

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

func loadBundle(spec *APISpec) {
  var err error

  if spec.CustomMiddlewareBundle == "" {
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

  bundlePath := strings.Join([]string{spec.APIID, spec.CustomMiddlewareBundle}, "-")
  log.Println("bundlePath =", bundlePath)
  destPath := filepath.Join("/Users/matias/dev/tyk", "middleware/bundles", bundlePath)
  log.Println("destPath =", destPath)

  if _, err := os.Stat(destPath); err == nil {
    log.Println("destPath exists!")
    // return
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

}
