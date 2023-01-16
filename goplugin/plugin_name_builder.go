package goplugin

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
)

// GetPluginFileNameToLoad check which file to load based on name, tyk version, os and architecture
// but it also takes care of returning the name of the file that exists
func GetPluginFileNameToLoad(pluginStorage Storage, path string, version string) (string, error) {

	prefixedGwVersion := getPrefixedVersion(version)
	newNamingFormat := getPluginNameFromTykVersion(prefixedGwVersion, path)

	// 1. attempt to load a plugin that follow the new standard
	if pluginStorage.FileExist(newNamingFormat) {
		return newNamingFormat, nil
	}

	// 2. attempt to load a plugin that follows the new standard but gw version is not prefixed
	if !strings.HasPrefix(version, "v") {
		newNamingFormat = getPluginNameFromTykVersion(version, path)

		if pluginStorage.FileExist(newNamingFormat) {
			return newNamingFormat, nil
		}
	}

	// 3. attempt to load the exact name provided
	if !pluginStorage.FileExist(path) {
		return "", errors.New("plugin file not found")
	}

	return path, nil
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
