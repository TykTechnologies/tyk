package goplugin

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	logger "github.com/TykTechnologies/tyk/log"
)

var log = logger.Get()

// GetPluginFileNameToLoad check which file to load based on name, tyk version, os and architecture
// but it also takes care of returning the name of the file that exists
func GetPluginFileNameToLoad(path string, version string) string {
	if !fileExist(path) {
		// if the exact name doesn't exist then try to load it using tyk version
		newPath := getPluginNameFromTykVersion(version, path)

		prefixedVersion := getPrefixedVersion(version)
		if !fileExist(newPath) && version != prefixedVersion {
			// if the file doesn't exist yet, then lets try with version in the format: v.x.x.x
			newPath = getPluginNameFromTykVersion(prefixedVersion, path)
		}
		path = newPath
	}

	return path
}

// getPluginNameFromTykVersion builds a name of plugin based on tyk version
// os and architecture. The structure of the plugin name looks like:
// {plugin-dir}/{plugin-name}_{GW-version}_{OS}_{arch}.so
// it doesn't check if the file exist
func getPluginNameFromTykVersion(version string, path string) string {
	if path == "" {
		return ""
	}

	pluginDir := filepath.Dir(path)
	// remove plugin extension to have the plugin's clean name
	pluginName := strings.TrimSuffix(filepath.Base(path), ".so")
	os := runtime.GOOS
	architecture := runtime.GOARCH

	// sanitize away `-rc15` suffixes (remove `-*`) from version
	vs := strings.Split(version, "-")
	if len(vs) > 0 {
		version = vs[0]
	}

	newPluginName := strings.Join([]string{pluginName, version, os, architecture}, "_")
	newPluginPath := pluginDir + "/" + newPluginName + ".so"

	return newPluginPath
}

// getPrefixedVersion receives a version and check that it has the prefix 'v' otherwise, it adds it
func getPrefixedVersion(version string) string {
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	return version
}

func fileExist(filepath string) bool {
	if _, err := os.Stat(filepath); errors.Is(err, os.ErrNotExist) {
		log.Warningf("plugin file %v doesn't exist", filepath)
		return false
	}
	return true
}
