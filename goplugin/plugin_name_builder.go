package goplugin

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/TykTechnologies/tyk/internal/build"
)

// GetPluginFileNameToLoad returns the plugin file to load for pluginPath.
// The candidates are tried in order and the first one that exists wins:
//
//  1. {plugin-dir}/{plugin-name}_v{GW-version}_{OS}_{arch}.so
//  2. {plugin-dir}/{plugin-name}_{GW-version}_{OS}_{arch}.so
//  3. pluginPath exactly as given
//
// Candidates that do not exist are only reported at debug level, since missing
// them is the expected outcome of the search. When none exists the returned
// error names every file that was tried.
func GetPluginFileNameToLoad(pluginStorage storage, pluginPath string) (string, error) {
	versionPrefixed := getPrefixedVersion()

	candidates := []string{
		getPluginNameFromTykVersion(versionPrefixed, pluginPath),
		getPluginNameFromTykVersion(versionPrefixed[1:], pluginPath),
		pluginPath,
	}

	for _, candidate := range candidates {
		if pluginStorage.fileExist(candidate) {
			return candidate, nil
		}
		log.Debugf("plugin file %v doesn't exist", candidate)
	}

	return "", fmt.Errorf("plugin file not found, tried: %s", strings.Join(candidates, ", "))
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
