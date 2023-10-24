package python

/*
#cgo LDFLAGS: -ldl

#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
*/
import "C"

import (
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"github.com/TykTechnologies/tyk/log"
)

var (
	errEmptyPath      = errors.New("Empty PATH")
	errLibNotFound    = errors.New("Library not found")
	errLibLoad        = errors.New("Couldn't load library")
	errOSNotSupported = errors.New("OS not supported")

	pythonExpr = regexp.MustCompile(`(^python3(\.)?(\d)?(m)?(\-config)?$)`)

	pythonConfigPath  string
	pythonLibraryPath string

	logger = log.Get().WithField("prefix", "dlpython")

	paths = os.Getenv("PATH")
)

// FindPythonConfig scans PATH for common python-config locations.
func FindPythonConfig(customVersion string) (selectedVersion string, err error) {
	// Not sure if this can be replaced with os.LookPath:
	if paths == "" {
		return selectedVersion, errEmptyPath
	}

	// Scan python-config binaries:
	pythonConfigBinaries := map[float64]string{}

	for _, p := range strings.Split(paths, ":") {
		if !strings.HasSuffix(p, "/bin") {
			continue
		}
		files, err := ioutil.ReadDir(p)
		if err != nil {
			continue
		}
		for _, f := range files {
			name := f.Name()
			fullPath := filepath.Join(p, name)
			matches := pythonExpr.FindAllStringSubmatch(name, -1)
			if len(matches) == 0 {
				continue
			}

			minorVersion := matches[0][3]
			pyMallocBuild := matches[0][4]
			isConfig := matches[0][5]
			versionStr := "3"
			if minorVersion != "" {
				versionStr += "." + minorVersion
			}
			if pyMallocBuild != "" {
				versionStr += pyMallocBuild
			}

			version, err := strconv.ParseFloat(versionStr, 64)
			if err != nil || isConfig == "" {
				continue
			}

			if _, exists := pythonConfigBinaries[version]; !exists {
				pythonConfigBinaries[version] = fullPath
			}
		}
	}

	if len(pythonConfigBinaries) == 0 {
		return selectedVersion, errors.New("No Python installations found")
	}

	for ver, binPath := range pythonConfigBinaries {
		logger.Debugf("Found python-config binary: %.1f (%s)", ver, binPath)
	}

	if customVersion == "" {
		var availableVersions []float64
		for v := range pythonConfigBinaries {
			availableVersions = append(availableVersions, v)
		}
		sort.Float64s(availableVersions)
		lastVersion := availableVersions[len(availableVersions)-1]
		pythonConfigPath = pythonConfigBinaries[lastVersion]
		selectedVersion = strconv.FormatFloat(lastVersion, 'f', -1, 64)
		logger.Debug("Using latest Python version")
	} else {
		prefixF, err := strconv.ParseFloat(customVersion, 64)
		if err != nil {
			return selectedVersion, errors.New("Couldn't parse Python version")
		}
		cfgPath, ok := pythonConfigBinaries[prefixF]
		if !ok {
			return selectedVersion, errors.New("No python-config was found for the specified version")
		}
		pythonConfigPath = cfgPath
		selectedVersion = customVersion
	}

	logger.Debugf("Selected Python configuration path: %s", pythonConfigPath)
	if err := getLibraryPathFromCfg(); err != nil {
		return selectedVersion, err
	}
	logger.Debugf("Selected Python library path: %s", pythonLibraryPath)
	return selectedVersion, nil
}

func execPythonConfig() ([]byte, error) {
	// Try to include the "embed" flag first
	// introduced in Python 3.8: https://docs.python.org/3.8/whatsnew/3.8.html#debug-build-uses-the-same-abi-as-release-build
	out, err := exec.Command(pythonConfigPath, "--ldflags", "--embed").Output()
	if err != nil {
		return exec.Command(pythonConfigPath, "--ldflags").Output()
	}
	return out, err
}

func getLibraryPathFromCfg() error {
	out, err := execPythonConfig()
	if err != nil {
		logger.Errorf("Error while executing command for python config path: %s", pythonConfigPath)
		return err
	}
	outString := string(out)
	var libDir, libName string
	splits := strings.Split(outString, " ")
	for _, v := range splits {
		if len(v) <= 2 {
			continue
		}
		prefix := v[0:2]
		switch prefix {
		case "-L":
			if libDir == "" {
				libDir = strings.Replace(v, prefix, "", -1)
			}
		case "-l":
			if strings.Contains(v, "python") {
				libName = strings.Replace(v, prefix, "", -1)
			}
		}
	}

	switch runtime.GOOS {
	case "darwin":
		libName = "lib" + libName + ".dylib"
	case "linux":
		libName = "lib" + libName + ".so"
	default:
		return errOSNotSupported
	}
	pythonLibraryPath = filepath.Join(libDir, libName)
	if _, err := os.Stat(pythonLibraryPath); os.IsNotExist(err) {
		return errLibNotFound
	}
	return nil
}

var libPath *C.char

// Init will initialize the Python runtime.
func Init() error {
	// Set the library path:
	libPath = C.CString(pythonLibraryPath)
	defer C.free(unsafe.Pointer(libPath))

	// Map API calls and initialize runtime:
	err := mapCalls()
	if err != nil {
		return err
	}
	Py_Initialize()
	return nil
}
