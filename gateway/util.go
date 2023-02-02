package gateway

import (
	"net"
	"net/url"
	"strconv"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

// appendIfMissing ensures dest slice is unique with new items.
func appendIfMissing(src []string, in ...string) []string {
	// Use map for uniqueness
	srcMap := map[string]bool{}
	for _, v := range src {
		srcMap[v] = true
	}
	for _, v := range in {
		srcMap[v] = true
	}

	// Produce unique []string, maintain sort order
	uniqueSorted := func(src []string, keys map[string]bool) []string {
		result := make([]string, 0, len(keys))
		for _, v := range src {
			// append missing value
			if val := keys[v]; val {
				result = append(result, v)
				delete(keys, v)
			}
		}
		return result
	}

	// no new items from `in`
	if len(srcMap) == len(src) {
		return src
	}

	src = uniqueSorted(src, srcMap)
	in = uniqueSorted(in, srcMap)

	return append(src, in...)
}

// intersection gets intersection of the given two slices.
func intersection(a []string, b []string) (inter []string) {
	m := make(map[string]bool)

	for _, item := range a {
		m[item] = true
	}

	for _, item := range b {
		if _, ok := m[item]; ok {
			inter = append(inter, item)
		}
	}

	return
}

// contains checks whether the given slice contains the given item.
func contains(s []string, i string) bool {
	for _, a := range s {
		if a == i {
			return true
		}
	}
	return false
}

// greaterThanFloat64 checks whether first float64 value is bigger than second float64 value.
// -1 means infinite and the biggest value.
func greaterThanFloat64(first, second float64) bool {
	if first == -1 {
		return true
	}

	if second == -1 {
		return false
	}

	return first > second
}

// greaterThanInt64 checks whether first int64 value is bigger than second int64 value.
// -1 means infinite and the biggest value.
func greaterThanInt64(first, second int64) bool {
	if first == -1 {
		return true
	}

	if second == -1 {
		return false
	}

	return first > second
}

// greaterThanInt checks whether first int value is bigger than second int value.
// -1 means infinite and the biggest value.
func greaterThanInt(first, second int) bool {
	if first == -1 {
		return true
	}

	if second == -1 {
		return false
	}

	return first > second
}

func getAPIURL(apiDef apidef.APIDefinition, gwConfig config.Config) string {
	var result = url.URL{
		Scheme: "http",
		Host:   apiDef.GetAPIDomain(),
		Path:   apiDef.Proxy.ListenPath,
	}

	if gwConfig.HttpServerOptions.UseSSL {
		result.Scheme = "https"
	}

	// apiDef has priority
	if result.Host != "" {
		return result.String()
	}

	result.Host = gwConfig.ListenAddress
	if gwConfig.HostName != "" {
		result.Host = gwConfig.HostName
	}

	if result.Host == "" {
		result.Host = "127.0.0.1"
	}

	// Skip adding ListenPort for http/80, https/443
	if result.Scheme == "http" && gwConfig.ListenPort == 80 ||
		result.Scheme == "https" && gwConfig.ListenPort == 443 {
		return result.String()
	}

	result.Host = net.JoinHostPort(result.Host, strconv.Itoa(gwConfig.ListenPort))

	return result.String()
}

func shouldReloadSpec(existingSpec, newSpec *APISpec) bool {
	if existingSpec == nil {
		return true
	}

	if existingSpec.Checksum != newSpec.Checksum {
		return true
	}

	if mwEnabled(newSpec.CustomMiddleware.AuthCheck) {
		return true
	}

	customPlugin := mwsEnabled(newSpec.CustomMiddleware.Pre)
	if customPlugin {
		return true
	}

	customPlugin = mwsEnabled(newSpec.CustomMiddleware.PostKeyAuth)
	if customPlugin {
		return true
	}

	customPlugin = mwsEnabled(newSpec.CustomMiddleware.Post)
	if customPlugin {
		return true
	}

	customPlugin = mwsEnabled(newSpec.CustomMiddleware.Response)

	return customPlugin
}

func mwsEnabled(mwDefs []apidef.MiddlewareDefinition) bool {
	for _, mwDef := range mwDefs {
		if mwEnabled(mwDef) {
			return true
		}
	}
	return false
}

func mwEnabled(mwDef apidef.MiddlewareDefinition) bool {
	return !mwDef.Disabled && mwDef.Path != "" && mwDef.Name != ""
}
