package bundler

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/TykTechnologies/goverify"
	"github.com/TykTechnologies/tyk/apidef"
	logger "github.com/TykTechnologies/tyk/log"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

const (
	cmdName = "bundle"
	cmdDesc = "Manage plugin bundles"

	defaultManifestPath = "manifest.json"
	defaultBundlePath   = "bundle.zip"
	defaultBundlePerm   = 0755
)

var (
	bundler *Bundler

	errNoHooks      = errors.New("No hooks defined")
	errNoDriver     = errors.New("No driver specified")
	errManifestLoad = errors.New("Couldn't load manifest file")
	errBundleData   = errors.New("Couldn't read/write bundle data")
	errBundleSign   = errors.New("Couldn't sign bundle")

	log = logger.Get().WithField("prefix", "tyk")
)

// Bundler wraps the bundler data structure.
type Bundler struct {
	keyPath      *string
	bundlePath   *string
	skipSigning  *bool
	manifestPath *string
}

func init() {
	bundler = &Bundler{}
}

// Bundle is the entrypoint function for this subcommand.
func (b *Bundler) Bundle(ctx *kingpin.ParseContext) error {
	return nil
}

// Build builds a bundle.
func (b *Bundler) Build(ctx *kingpin.ParseContext) error {
	manifestPath := *b.manifestPath
	bundlePath := *b.bundlePath
	skipSigning := *b.skipSigning
	key := *b.keyPath

	log.Infof("Building bundle using '%s'", manifestPath)
	manifest, err := b.loadManifest(manifestPath)
	if err != nil {
		return err
	}
	if bundlePath == defaultBundlePath {
		log.Warningf("Using default bundle path '%s'", defaultBundlePath)
	}

	// Write the file:
	bundleBuf := new(bytes.Buffer)
	for _, file := range manifest.FileList {
		var data []byte
		data, err = ioutil.ReadFile(file)
		if err != nil {
			break
		}
		bundleBuf.Write(data)
	}
	if err != nil {
		return err
	}

	// Compute the checksum and append it to the manifest data structure:
	manifest.Checksum = fmt.Sprintf("%x", md5.Sum(bundleBuf.Bytes()))

	if key == "" {
		if skipSigning {
			log.Warning("The bundle will be unsigned")
		} else {
			log.Warning("The bundle will be unsigned, type \"y\" or \"yes\" to confirm:")
			reader := bufio.NewReader(os.Stdin)
			text, _ := reader.ReadString('\n')
			ch := text[0:1]
			if ch != "y" {
				log.Fatal("Aborting")
			}
		}
	} else {
		err = b.sign(key, manifest, bundleBuf)
		if err != nil {
			return err
		}
	}

	manifestData, err := json.Marshal(&manifest)
	if err != nil {
		return err
	}

	// Write the ZIP contents into a buffer:
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)
	for _, file := range manifest.FileList {
		var outputFile io.Writer
		outputFile, err = zipWriter.Create(file)
		if err != nil {
			break
		}
		var data []byte
		data, err = ioutil.ReadFile(file)
		if err != nil {
			break
		}
		if _, err = outputFile.Write(data); err != nil {
			break
		}
	}
	if err != nil {
		return err
	}

	// Append the updated manifest file to the ZIP file:
	newManifest, err := zipWriter.Create(defaultManifestPath)
	_, err = newManifest.Write(manifestData)
	zipWriter.Close()
	err = ioutil.WriteFile(bundlePath, buf.Bytes(), defaultBundlePerm)
	if err != nil {
		return err
	}
	log.Infof("Wrote '%s' (%d bytes)", bundlePath, buf.Len())
	return nil
}

func (b *Bundler) sign(key string, manifest *apidef.BundleManifest, bundle *bytes.Buffer) (err error) {
	signer, err := goverify.LoadPrivateKeyFromFile(key)
	if err != nil {
		return err
	}
	signed, err := signer.Sign(bundle.Bytes())
	if err != nil {
		return err
	}
	manifest.Signature = base64.StdEncoding.EncodeToString(signed)
	log.Infof("Signing bundle with key '%s'", key)
	return nil
}

func (b *Bundler) validateManifest(manifest *apidef.BundleManifest) (err error) {
	for _, f := range manifest.FileList {
		if _, err := os.Stat(f); err != nil {
			err = errors.New("Referencing a nonexistent file: " + f)
			return err
		}
	}

	// The custom middleware block must specify at least one hook:
	definedHooks := len(manifest.CustomMiddleware.Pre) + len(manifest.CustomMiddleware.Post) + len(manifest.CustomMiddleware.PostKeyAuth) + len(manifest.CustomMiddleware.Response)

	// We should count the auth check middleware (single), if it's present:
	if manifest.CustomMiddleware.AuthCheck.Name != "" {
		definedHooks++
	}

	if definedHooks == 0 {
		return errNoHooks
	}

	// The custom middleware block must specify a driver:
	if manifest.CustomMiddleware.Driver == "" {
		return errNoDriver
	}

	return nil
}

func (b *Bundler) loadManifest(path string) (manifest *apidef.BundleManifest, err error) {
	rawManifest, err := ioutil.ReadFile(path)
	if err != nil {
		return manifest, errManifestLoad
	}
	err = json.Unmarshal(rawManifest, &manifest)
	if err != nil {
		return manifest, err
	}
	err = b.validateManifest(manifest)
	if err != nil {
		return manifest, err
	}
	return manifest, err
}

// AddTo initializes an importer object.
func AddTo(app *kingpin.Application) {
	cmd := app.Command(cmdName, cmdDesc)

	buildCmd := cmd.Command("build", "Build a new plugin bundle using a manifest file and its specified files")
	bundler.keyPath = buildCmd.Flag("key", "Key for bundle signature").Short('k').String()
	bundler.bundlePath = buildCmd.Flag("output", "Output file").Short('o').Default(defaultBundlePath).String()
	bundler.skipSigning = buildCmd.Flag("skip-signing", "Skip bundle signing").Short('y').Bool()
	bundler.manifestPath = buildCmd.Flag("manifest", "Path to manifest file").Default(defaultManifestPath).Short('m').String()
	buildCmd.Action(bundler.Build)
}
