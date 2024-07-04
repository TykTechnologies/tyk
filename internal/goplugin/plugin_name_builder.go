package goplugin

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/TykTechnologies/tyk/internal/build"
)

// GetPluginFileNameToLoad check which file to load based on name, tyk version, os and architecture
// but it also takes care of returning the name of the file that exists
func GetPluginFileNameToLoad(pluginStorage storage, pluginPath string) (string, error) {
	var (
		versionPrefixed = getPrefixedVersion()
		version         = versionPrefixed[1:]
	)

	// 1. attempt to load a plugin that follow the new standard
	newNamingFormat := getPluginNameFromTykVersion(versionPrefixed, pluginPath)
	if pluginStorage.fileExist(newNamingFormat) {
		return newNamingFormat, nil
	}

	// 2. attempt to load a plugin that follows the new standard but gw version is not prefixed
	newNamingFormat = getPluginNameFromTykVersion(version, pluginPath)
	if pluginStorage.fileExist(newNamingFormat) {
		return newNamingFormat, nil
	}

	// 3. attempt to load the exact name provided
	if !pluginStorage.fileExist(pluginPath) {
		return "", errors.New("plugin file not found")
	}

	return pluginPath, nil
}

// getPluginNameFromTykVersion builds a name of plugin based on tyk version,
// GOOS, and GOARCH of the build. The structure of the plugin name looks like:
// {plugin-dir}/{plugin-name}_{GW-version}_{OS}_{arch}.so
func getPluginNameFromTykVersion(version string, pluginPath string) string {
	if pluginPath == "" {
		return ""
	}

	// remove plugin extension to have the plugin's clean name
	pluginName := strings.TrimSuffix(filepath.Base(pluginPath), ".so")
	pluginDir := filepath.Dir(pluginPath)

	// produce a `name_{version}_{goos}_{goarch}` for loading
	newPluginName := strings.Join([]string{pluginName, version, runtime.GOOS, runtime.GOARCH}, "_")
	newPluginPath := pluginDir + "/" + newPluginName + ".so"

	return newPluginPath
}

// getPrefixedVersion takes the injected build.Version and ensures
// it's returned containing a `v` prefix. It cleans up any rc tags
// that are delimited with a `-`.
func getPrefixedVersion() string {
	version := build.Version
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	// sanitize away `-rc15`-like suffixes (remove `-*`) from version
	if strings.Contains(version, "-") {
		vs := strings.SplitN(version, "-", 2)
		version = vs[0]
	}
	return version
}
