package apidef

import (
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/TykTechnologies/tyk/internal/reflect"
	"github.com/TykTechnologies/tyk/internal/uuid"
)

const (
	ResponseProcessorResponseBodyTransform = "response_body_transform"
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

			apiID := uuid.NewHex()

			newAPI.APIID = apiID
			newAPI.Id = ""
			newAPI.Name += "-" + url.QueryEscape(vName)
			newAPI.Internal = true

			listenPathClean := strings.TrimSuffix(newAPI.Proxy.ListenPath, "/")
			if listenPathClean == "" {
				listenPathClean = "/" + url.QueryEscape(vName) + "/"
			} else {
				listenPathClean += "-" + url.QueryEscape(vName) + "/"
			}

			newAPI.Proxy.ListenPath = listenPathClean

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
	a.migrateCustomPluginAuth()
	a.MigrateAuthentication()
	a.migratePluginBundle()
	a.migratePluginConfigData()
	a.migrateMutualTLS()
	a.migrateCertificatePinning()
	a.migrateGatewayTags()
	a.migrateAuthenticationPlugin()
	a.migrateIDExtractor()
	a.migrateCustomDomain()
	a.migrateScopeToPolicy()
	a.migrateResponseProcessors()
	a.migrateGlobalRateLimit()
	a.migrateIPAccessControl()

	versions, err = a.MigrateVersioning()
	if err != nil {
		return nil, err
	}

	a.MigrateEndpointMeta()
	a.MigrateCachePlugin()
	a.migrateGlobalHeaders()
	a.migrateGlobalResponseHeaders()
	for i := 0; i < len(versions); i++ {
		versions[i].MigrateEndpointMeta()
		versions[i].MigrateCachePlugin()
		versions[i].migrateGlobalHeaders()
		versions[i].migrateGlobalResponseHeaders()
	}

	return versions, nil
}

func (a *APIDefinition) migratePluginBundle() {
	if !a.CustomMiddlewareBundleDisabled && a.CustomMiddlewareBundle == "" {
		a.CustomMiddlewareBundleDisabled = true
	}
}

func (a *APIDefinition) migratePluginConfigData() {
	if reflect.IsEmpty(a.ConfigData) {
		a.ConfigDataDisabled = true
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
	if reflect.IsEmpty(a.CustomMiddleware.AuthCheck) {
		a.CustomMiddleware.AuthCheck.Disabled = true
	}
}

func (a *APIDefinition) migrateIDExtractor() {
	if reflect.IsEmpty(a.CustomMiddleware.IdExtractor) {
		a.CustomMiddleware.IdExtractor.Disabled = true
	}
}

func (a *APIDefinition) migrateCustomDomain() {
	if !a.DomainDisabled && a.Domain == "" {
		a.DomainDisabled = true
	}
}

func (a *APIDefinition) migrateGlobalHeaders() {
	vInfo := a.VersionData.Versions[""]
	if len(vInfo.GlobalHeaders) == 0 && len(vInfo.GlobalHeadersRemove) == 0 {
		vInfo.GlobalHeadersDisabled = true
		a.VersionData.Versions[""] = vInfo
	}
}

func (a *APIDefinition) migrateGlobalResponseHeaders() {
	vInfo := a.VersionData.Versions[""]
	if len(vInfo.GlobalResponseHeaders) == 0 && len(vInfo.GlobalResponseHeadersRemove) == 0 {
		vInfo.GlobalResponseHeadersDisabled = true
		a.VersionData.Versions[""] = vInfo
	}
}

func (a *APIDefinition) MigrateCachePlugin() {
	vInfo := a.VersionData.Versions[""]
	list := vInfo.ExtendedPaths.Cached

	timeout := int64(60)

	if a.CacheOptions.CacheTimeout > 0 {
		timeout = a.CacheOptions.CacheTimeout
	}

	if vInfo.UseExtendedPaths && len(list) > 0 {
		var advCacheMethods []CacheMeta
		for _, cache := range list {
			newGetMethodCache := CacheMeta{
				Path:    cache,
				Method:  http.MethodGet,
				Timeout: timeout,
			}
			newHeadMethodCache := CacheMeta{
				Path:    cache,
				Method:  http.MethodHead,
				Timeout: timeout,
			}
			newOptionsMethodCache := CacheMeta{
				Path:    cache,
				Method:  http.MethodOptions,
				Timeout: timeout,
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

	if !a.CustomPluginAuthEnabled || (a.CustomPluginAuthEnabled && a.CustomMiddleware.Driver == GoPluginDriver) {
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
			!a.CustomPluginAuthEnabled &&
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
	a.CustomMiddleware.IdExtractor.Disabled = true
	a.ConfigDataDisabled = true
	a.Proxy.ServiceDiscovery.CacheDisabled = true
	a.UptimeTests.Config.ServiceDiscovery.CacheDisabled = true
	for i := 0; i < len(a.CustomMiddleware.Pre); i++ {
		a.CustomMiddleware.Pre[i].Disabled = true
	}

	for i := 0; i < len(a.CustomMiddleware.PostKeyAuth); i++ {
		a.CustomMiddleware.PostKeyAuth[i].Disabled = true
	}

	for i := 0; i < len(a.CustomMiddleware.Post); i++ {
		a.CustomMiddleware.Post[i].Disabled = true
	}

	for i := 0; i < len(a.CustomMiddleware.Response); i++ {
		a.CustomMiddleware.Response[i].Disabled = true
	}

	for version := range a.VersionData.Versions {
		for i := 0; i < len(a.VersionData.Versions[version].ExtendedPaths.Virtual); i++ {
			a.VersionData.Versions[version].ExtendedPaths.Virtual[i].Disabled = true
		}

		for i := 0; i < len(a.VersionData.Versions[version].ExtendedPaths.GoPlugin); i++ {
			a.VersionData.Versions[version].ExtendedPaths.GoPlugin[i].Disabled = true
		}
	}

	if a.GlobalRateLimit.Per <= 0 || a.GlobalRateLimit.Rate <= 0 {
		a.GlobalRateLimit.Disabled = true
	}

	a.DoNotTrack = true

	a.setEventHandlersDisabledFlags()
}

func (a *APIDefinition) setEventHandlersDisabledFlags() {
	for k := range a.EventHandlers.Events {
		for i := range a.EventHandlers.Events[k] {
			if a.EventHandlers.Events[k][i].HandlerMeta != nil {
				a.EventHandlers.Events[k][i].HandlerMeta["disabled"] = true
			}
		}
	}
}

func (a *APIDefinition) migrateScopeToPolicy() {
	scopeClaim := ScopeClaim{
		ScopeClaimName: a.JWTScopeClaimName,
		ScopeToPolicy:  a.JWTScopeToPolicyMapping,
	}

	a.JWTScopeToPolicyMapping = nil
	a.JWTScopeClaimName = ""

	if a.UseOpenID {
		a.Scopes.OIDC = scopeClaim
		return
	}

	a.Scopes.JWT = scopeClaim
}

func (a *APIDefinition) migrateResponseProcessors() {
	var responseProcessors []ResponseProcessor
	for i := range a.ResponseProcessors {
		if a.ResponseProcessors[i].Name == ResponseProcessorResponseBodyTransform {
			continue
		}
		responseProcessors = append(responseProcessors, a.ResponseProcessors[i])
	}

	a.ResponseProcessors = responseProcessors
}

func (a *APIDefinition) migrateGlobalRateLimit() {
	if a.GlobalRateLimit.Per <= 0 || a.GlobalRateLimit.Rate <= 0 {
		a.GlobalRateLimit.Disabled = true
	}
}

func (a *APIDefinition) migrateIPAccessControl() {
	a.IPAccessControlDisabled = false

	if a.EnableIpBlacklisting && len(a.BlacklistedIPs) > 0 {
		return
	}

	if a.EnableIpWhiteListing && len(a.AllowedIPs) > 0 {
		return
	}

	a.IPAccessControlDisabled = true
}
