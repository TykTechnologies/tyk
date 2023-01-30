package apidef

import (
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"

	uuid "github.com/satori/go.uuid"
)

var (
	ErrMigrationNewVersioningEnabled = errors.New("not migratable - new versioning is already enabled")
)

func (a *APIDefinition) MigrateVersioning() (versions []APIDefinition, err error) {
	if a.VersionDefinition.Enabled || len(a.VersionDefinition.Versions) != 0 {
		return nil, ErrMigrationNewVersioningEnabled
	}

	if a.VersionData.NotVersioned && len(a.VersionData.Versions) > 1 {
		return nil, errors.New("not migratable - if not versioned, there should be just one version info in versions map")
	}

	a.VersionDefinition.Enabled = !a.VersionData.NotVersioned
	if a.VersionDefinition.Enabled {
		a.VersionDefinition.Default = Self
	}

	base := a.VersionData.DefaultVersion
	var baseVInfo VersionInfo
	var found bool
	if baseVInfo, found = a.VersionData.Versions[base]; !found {
		a.VersionDefinition.Default = ""
		base = "Default"
		if baseVInfo, found = a.VersionData.Versions[base]; !found {
			var sortedVersionNames []string
			for vName := range a.VersionData.Versions {
				sortedVersionNames = append(sortedVersionNames, vName)
			}

			sort.Strings(sortedVersionNames)
			if len(sortedVersionNames) > 0 {
				base = sortedVersionNames[0]
			}

			baseVInfo = a.VersionData.Versions[base]
		}
	}

	delete(a.VersionData.Versions, base)
	a.VersionName = base

	if a.VersionDefinition.Enabled {
		a.VersionDefinition.Name = base

		for vName, vInfo := range a.VersionData.Versions {
			newAPI := *a

			newID := uuid.NewV4()
			apiID := strings.Replace(newID.String(), "-", "", -1)

			newAPI.APIID = apiID
			newAPI.Id = ""
			newAPI.Name += "-" + url.QueryEscape(vName)
			newAPI.Internal = true
			newAPI.Proxy.ListenPath = strings.TrimSuffix(newAPI.Proxy.ListenPath, "/") + "-" + url.QueryEscape(vName) + "/"
			newAPI.VersionDefinition = VersionDefinition{BaseID: a.APIID}
			newAPI.VersionName = vName

			// Version API Expires migration
			newAPI.Expiration = vInfo.Expires
			vInfo.Expires = ""

			// Version API OverrideTarget migration
			if vInfo.OverrideTarget != "" {
				newAPI.Proxy.TargetURL = vInfo.OverrideTarget
				vInfo.OverrideTarget = ""
			}

			newAPI.VersionData = VersionData{
				NotVersioned: true,
				Versions: map[string]VersionInfo{
					"": vInfo,
				},
			}

			if a.VersionDefinition.Versions == nil {
				a.VersionDefinition.Versions = make(map[string]string)
			}

			a.VersionDefinition.Versions[vName] = newAPI.APIID

			versions = append(versions, newAPI)
		}

		sort.Slice(versions, func(i, j int) bool {
			return versions[i].VersionName < versions[j].VersionName
		})
	}

	// Base API StripPath migration
	if a.VersionDefinition.Location == URLLocation {
		a.VersionDefinition.StripVersioningData = a.VersionDefinition.StripPath
	}

	a.VersionDefinition.StripPath = false

	// Base API Expires migration
	if a.VersionDefinition.Enabled {
		a.Expiration = baseVInfo.Expires
	}

	baseVInfo.Expires = ""

	// Base API OverrideTarget migration
	if baseVInfo.OverrideTarget != "" {
		a.Proxy.TargetURL = baseVInfo.OverrideTarget
		baseVInfo.OverrideTarget = ""
	}

	a.VersionData = VersionData{
		NotVersioned: true,
		Versions: map[string]VersionInfo{
			"": baseVInfo,
		},
	}

	// If versioning is not enabled and versions list are empty at this point, ignore key and location and drop them too.
	if !a.VersionDefinition.Enabled && len(versions) == 0 {
		a.VersionDefinition = VersionDefinition{}
	}

	return
}

const (
	typeWhitelist = 0
	typeBlacklist = 1
	typeIgnore    = 2
)

func (a *APIDefinition) MigrateEndpointMeta() {
	a.migrateEndpointMetaByType(typeIgnore)
	a.migrateEndpointMetaByType(typeBlacklist)
	a.migrateEndpointMetaByType(typeWhitelist)
}

func (a *APIDefinition) migrateEndpointMetaByType(typ int) {
	vInfo := a.VersionData.Versions[""]

	list := vInfo.ExtendedPaths.WhiteList
	if typ == typeBlacklist {
		list = vInfo.ExtendedPaths.BlackList
	} else if typ == typeIgnore {
		list = vInfo.ExtendedPaths.Ignored
	}

	var resList []EndPointMeta
	var resMockResponse []MockResponseMeta
	for _, meta := range list {
		var tempList []EndPointMeta
		var tempMockResponse []MockResponseMeta
		for method, action := range meta.MethodActions {
			newMeta := meta
			newMeta.Method = method

			newMeta.MethodActions = nil
			tempList = append(tempList, newMeta)

			if action.Action == NoAction {
				continue
			}

			mockMeta := MockResponseMeta{Path: meta.Path, IgnoreCase: meta.IgnoreCase}
			mockMeta.Disabled = meta.Disabled || (!meta.Disabled && action.Action != Reply)
			mockMeta.Method = method
			mockMeta.Code = action.Code
			mockMeta.Body = action.Data
			mockMeta.Headers = action.Headers

			tempMockResponse = append(tempMockResponse, mockMeta)
		}

		sort.Slice(tempList, func(i, j int) bool {
			return tempList[i].Method < tempList[j].Method
		})

		resList = append(resList, tempList...)

		sort.Slice(tempMockResponse, func(i, j int) bool {
			return tempMockResponse[i].Method < tempMockResponse[j].Method
		})

		resMockResponse = append(resMockResponse, tempMockResponse...)
	}

	if typ == typeBlacklist {
		vInfo.ExtendedPaths.BlackList = resList
	} else if typ == typeIgnore {
		vInfo.ExtendedPaths.Ignored = resList
	} else {
		vInfo.ExtendedPaths.WhiteList = resList
	}

	for _, search := range resMockResponse {
		contains := false
		for _, mock := range vInfo.ExtendedPaths.MockResponse {
			if mock.Path == search.Path && mock.Method == search.Method {
				contains = true
				break
			}
		}

		if !contains {
			vInfo.ExtendedPaths.MockResponse = append(vInfo.ExtendedPaths.MockResponse, search)
		}
	}

	a.VersionData.Versions[""] = vInfo
}

func (a *APIDefinition) Migrate() (versions []APIDefinition, err error) {
	a.MigrateAuthentication()
	a.migratePluginBundle()
	a.migrateCustomPluginAuth()
	a.migrateMutualTLS()
	a.migrateCertificatePinning()
	a.migrateGatewayTags()
	a.migrateAuthenticationPlugin()
	a.migrateCustomDomain()

	versions, err = a.MigrateVersioning()
	if err != nil {
		return nil, err
	}

	a.MigrateEndpointMeta()
	a.MigrateCachePlugin()
	for i := 0; i < len(versions); i++ {
		versions[i].MigrateEndpointMeta()
		versions[i].MigrateCachePlugin()
	}

	return versions, nil
}

func (a *APIDefinition) migratePluginBundle() {
	if !a.CustomMiddlewareBundleDisabled && a.CustomMiddlewareBundle == "" {
		a.CustomMiddlewareBundleDisabled = true
	}
}

// migrateCustomPluginAuth deprecates UseGoPluginAuth and EnableCoProcessAuth in favour of CustomPluginAuthEnabled.
func (a *APIDefinition) migrateCustomPluginAuth() {
	if a.UseGoPluginAuth || a.EnableCoProcessAuth {
		a.CustomPluginAuthEnabled = true
		a.UseGoPluginAuth = false
		a.EnableCoProcessAuth = false
	}
}

func (a *APIDefinition) migrateMutualTLS() {
	if !a.UpstreamCertificatesDisabled && len(a.UpstreamCertificates) == 0 {
		a.UpstreamCertificatesDisabled = true
	}
}

func (a *APIDefinition) migrateCertificatePinning() {
	if !a.CertificatePinningDisabled && len(a.PinnedPublicKeys) == 0 {
		a.CertificatePinningDisabled = true
	}
}

func (a *APIDefinition) migrateGatewayTags() {
	if !a.TagsDisabled && len(a.Tags) == 0 {
		a.TagsDisabled = true
	}
}

func (a *APIDefinition) migrateAuthenticationPlugin() {
	if reflect.DeepEqual(a.CustomMiddleware.AuthCheck, MiddlewareDefinition{}) {
		a.CustomMiddleware.AuthCheck.Disabled = true
	}
}

func (a *APIDefinition) migrateCustomDomain() {
	if !a.DomainDisabled && a.Domain == "" {
		a.DomainDisabled = true
	}
}

func (a *APIDefinition) MigrateCachePlugin() {
	vInfo := a.VersionData.Versions[""]
	list := vInfo.ExtendedPaths.Cached

	if vInfo.UseExtendedPaths && len(list) > 0 {
		var advCacheMethods []CacheMeta
		for _, cache := range list {
			newGetMethodCache := CacheMeta{
				Path:   cache,
				Method: http.MethodGet,
			}
			newHeadMethodCache := CacheMeta{
				Path:   cache,
				Method: http.MethodHead,
			}
			newOptionsMethodCache := CacheMeta{
				Path:   cache,
				Method: http.MethodOptions,
			}
			advCacheMethods = append(advCacheMethods, newGetMethodCache, newHeadMethodCache, newOptionsMethodCache)
		}

		vInfo.ExtendedPaths.AdvanceCacheConfig = advCacheMethods
		// reset cache to empty
		vInfo.ExtendedPaths.Cached = nil
	}

	a.VersionData.Versions[""] = vInfo
}

func (a *APIDefinition) MigrateAuthentication() {
	a.deleteAuthConfigsNotUsed()
	for k, v := range a.AuthConfigs {
		v.Name = k
		a.AuthConfigs[k] = v
	}
}

func (a *APIDefinition) deleteAuthConfigsNotUsed() {
	if !a.isAuthTokenEnabled() {
		delete(a.AuthConfigs, AuthTokenType)
	}

	if !a.EnableJWT {
		delete(a.AuthConfigs, JWTType)
	}

	if !a.EnableSignatureChecking {
		delete(a.AuthConfigs, HMACType)
	}

	if !a.UseBasicAuth {
		delete(a.AuthConfigs, BasicType)
	}

	if !a.EnableCoProcessAuth {
		delete(a.AuthConfigs, CoprocessType)
	}

	if !a.UseOauth2 {
		delete(a.AuthConfigs, OAuthType)
	}

	if !a.ExternalOAuth.Enabled {
		delete(a.AuthConfigs, ExternalOAuthType)
	}

	if !a.UseOpenID {
		delete(a.AuthConfigs, OIDCType)
	}
}

func (a *APIDefinition) isAuthTokenEnabled() bool {
	return a.UseStandardAuth ||
		(!a.UseKeylessAccess &&
			!a.EnableJWT &&
			!a.EnableSignatureChecking &&
			!a.UseBasicAuth &&
			!a.EnableCoProcessAuth &&
			!a.UseOauth2 &&
			!a.ExternalOAuth.Enabled &&
			!a.UseOpenID)
}

// SetDisabledFlags set disabled flags to true, since by default they are not enabled in OAS API definition.
func (a *APIDefinition) SetDisabledFlags() {
	a.CustomMiddleware.AuthCheck.Disabled = true
	a.TagsDisabled = true
	a.UpstreamCertificatesDisabled = true
	a.CertificatePinningDisabled = true
	a.DomainDisabled = true
	a.CustomMiddlewareBundleDisabled = true
	for i := 0; i < len(a.CustomMiddleware.Pre); i++ {
		a.CustomMiddleware.Pre[i].Disabled = true
	}

	for i := 0; i < len(a.CustomMiddleware.PostKeyAuth); i++ {
		a.CustomMiddleware.PostKeyAuth[i].Disabled = true
	}
}
