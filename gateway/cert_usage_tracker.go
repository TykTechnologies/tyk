package gateway

import (
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/model"
)

const (
	// serverCertsUser and gatewayConfigUser stand in for an API ID when a certificate is
	// referenced by the Gateway configuration instead of an API.
	serverCertsUser   = "__server__"
	gatewayConfigUser = "__gateway_config__"
)

// Gateway configuration settings that can use a certificate, as reported to the control plane.
const (
	certSettingServer     = "http_server_options.ssl_certificates"
	certSettingUpstream   = "security.certificates.upstream"
	certSettingAPIs       = "security.certificates.apis"
	certSettingControlAPI = "security.certificates.control_api"
	certSettingPinnedKeys = "security.pinned_public_keys"
)

func externalServiceCertSetting(service string) string {
	return "external_services." + service + ".mtls"
}

// certUsageTracker tracks which certificates the Gateway uses, through its loaded APIs and its configuration.
type certUsageTracker struct {
	mu sync.RWMutex

	apis map[string]map[string]struct{} // certID -> set of API IDs referencing this cert, whether the use is active or not

	report []model.CertificateUsage // certificates in active use, as reported to the control plane
}

func newUsageTracker() *certUsageTracker {
	return &certUsageTracker{
		apis:   make(map[string]map[string]struct{}),
		report: []model.CertificateUsage{},
	}
}

// Required returns true if the certificate is referenced by any loaded API or by the Gateway configuration.
func (cr *certUsageTracker) Required(certID string) bool {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	_, exists := cr.apis[certID]
	return exists
}

// APIs returns the IDs of APIs that use this certificate.
func (cr *certUsageTracker) APIs(certID string) []string {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	apiSet := cr.apis[certID]
	if apiSet == nil {
		return nil
	}

	// Convert set to slice
	result := make([]string, 0, len(apiSet))
	for apiID := range apiSet {
		result = append(result, apiID)
	}
	return result
}

// Report returns the certificates in active use, as reported to the control plane.
// It is never nil, and must not be modified.
func (cr *certUsageTracker) Report() []model.CertificateUsage {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.report
}

// ReplaceAll atomically replaces the entire certificate usage map.
// This method is thread-safe and ensures no partial state is visible to concurrent readers.
func (cr *certUsageTracker) ReplaceAll(newApis map[string]map[string]struct{}) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	cr.apis = newApis
}

// replace atomically replaces the usage map and the report with the ones collected by u.
func (cr *certUsageTracker) replace(u *certUsage) {
	report := u.buildReport()

	cr.mu.Lock()
	defer cr.mu.Unlock()

	cr.apis = u.references
	cr.report = report
}

// Len returns the number of required certificates.
func (cr *certUsageTracker) Len() int {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return len(cr.apis)
}

// Certs returns all required certificate IDs.
func (cr *certUsageTracker) Certs() []string {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	ids := make([]string, 0, len(cr.apis))
	for id := range cr.apis {
		ids = append(ids, id)
	}
	return ids
}

// certUsage is the certificate usage collected from a set of API specs and the Gateway configuration.
// It is built offline, with no locks held, then swapped into the tracker.
type certUsage struct {
	// references drives selective certificate sync, so it holds every certificate reference,
	// including uses that are switched off, keyed by the value as configured.
	references map[string]map[string]struct{}

	// config and apis hold the active uses, keyed by report ID (see reportID).
	config map[string]map[string]struct{}
	apis   map[string]map[string]struct{}

	reportIDs map[string]string
}

func newCertUsage() *certUsage {
	return &certUsage{
		references: make(map[string]map[string]struct{}),
		config:     make(map[string]map[string]struct{}),
		apis:       make(map[string]map[string]struct{}),
		reportIDs:  make(map[string]string),
	}
}

func addToSet(m map[string]map[string]struct{}, key, value string) {
	if m[key] == nil {
		m[key] = make(map[string]struct{})
	}
	m[key][value] = struct{}{}
}

// reference records that user (an API ID, or a stand-in for the Gateway configuration) references certID.
//
// Inline PEM values (recognised by certs.IsPEMContent) are deliberately
// excluded: the references exist to drive RPC/MDCB cert sync, and
// embedded PEMs are inline content that doesn't need to be fetched or
// synced. Including them would also bloat the map with multi-KB string
// keys.
func (u *certUsage) reference(certID, user string) {
	if certID == "" || certs.IsPEMContent(certID) {
		return
	}
	addToSet(u.references, certID, user)
}

func (u *certUsage) useByAPI(certID, apiID string, publicKey bool) {
	if id := u.reportID(certID, publicKey); id != "" {
		addToSet(u.apis, id, apiID)
	}
}

func (u *certUsage) useByConfig(certID, setting string, publicKey bool) {
	if id := u.reportID(certID, publicKey); id != "" {
		addToSet(u.config, id, setting)
	}
}

// reportID returns the ID a certificate is reported under. A certificate store ID is reported as is.
// A certificate set by file path or inline is reported by the fingerprint the certificate store would
// give it, which the control plane matches against the store ID of the same certificate. publicKey is
// true for pinned public keys, which are fingerprinted as pinning reads them. It returns "" for a
// value that can't be read, so a mistyped path is never reported.
func (u *certUsage) reportID(value string, publicKey bool) string {
	if certs.IsStoreID(value) {
		return value
	}

	cacheKey := value
	if publicKey {
		cacheKey = "pub:" + value
	}
	if id, ok := u.reportIDs[cacheKey]; ok {
		return id
	}

	var data []byte
	if certs.IsPEMContent(value) {
		data = []byte(value)
	} else if info, err := os.Stat(value); err == nil && info.Mode().IsRegular() {
		if data, err = os.ReadFile(value); err != nil {
			log.WithError(err).WithField("path", value).Debug("Can't read certificate file to report its use")
		}
	}

	id := ""
	if len(data) > 0 {
		if publicKey {
			id = certs.PublicKeyFingerprint(data)
		} else {
			id = certs.CertificateFingerprint(data)
		}
	}

	u.reportIDs[cacheKey] = id
	return id
}

func (u *certUsage) buildReport() []model.CertificateUsage {
	ids := make([]string, 0, len(u.config)+len(u.apis))
	for id := range u.config {
		ids = append(ids, id)
	}
	for id := range u.apis {
		if _, ok := u.config[id]; !ok {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)

	sortedKeys := func(set map[string]struct{}) []string {
		if len(set) == 0 {
			return nil
		}
		keys := make([]string, 0, len(set))
		for k := range set {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		return keys
	}

	report := make([]model.CertificateUsage, 0, len(ids))
	for _, id := range ids {
		report = append(report, model.CertificateUsage{
			CertID:        id,
			GatewayConfig: sortedKeys(u.config[id]),
			APIIDs:        sortedKeys(u.apis[id]),
		})
	}
	return report
}

// specCertificateReferences lists every place the API definition names a certificate.
func specCertificateReferences(spec *APISpec) apidef.CertificateReferences {
	if spec.IsOAS && spec.OAS.GetTykExtension() != nil {
		return spec.OAS.CertificateReferences(spec.HmacAllowedAlgorithms)
	}
	return spec.APIDefinition.CertificateReferences()
}

// specServesTLS reports whether the API's listener serves TLS. An API without a protocol takes the
// Gateway's, which is https only when use_ssl is on.
func specServesTLS(conf *config.Config, spec *APISpec) bool {
	switch spec.Protocol {
	case "https", "tls":
		return true
	case "":
		return conf.HttpServerOptions.UseSSL
	default:
		return false
	}
}

// servesTLS reports whether the Gateway serves TLS: on its own port, or on an API's own port.
func servesTLS(conf *config.Config, specs []*APISpec) bool {
	if conf.HttpServerOptions.UseSSL {
		return true
	}
	return slices.ContainsFunc(specs, func(spec *APISpec) bool {
		return (spec.Protocol == "https" || spec.Protocol == "tls") && spec.ListenPort != 0 && spec.ListenPort != conf.ListenPort
	})
}

// collectCertUsage collects the certificates used by the API specs and the Gateway configuration.
//
// Every reference counts for selective certificate sync, so that a use can be switched back on
// without delay. Only active uses are reported: an API's use is active when the apidef package
// says it is switched on, and a configuration setting is active only when the Gateway reads it.
// security.certificates.dashboard_api and security.certificates.mdcb_api are never read.
func collectCertUsage(conf *config.Config, specs []*APISpec) *certUsage {
	u := newCertUsage()

	for _, spec := range specs {
		for _, ref := range specCertificateReferences(spec) {
			u.reference(ref.CertID, spec.APIID)
			// The Gateway serves every API it loads, whatever its active flag says
			// (the Dashboard only sends active APIs), so only the use's own switch matters.
			// An API's server certificates are only read by a TLS listener.
			if ref.Active(true) && (ref.Type != apidef.CertificateUseServer || specServesTLS(conf, spec)) {
				u.useByAPI(ref.CertID, spec.APIID, ref.Type == apidef.CertificateUsePinned)
			}
		}
	}

	addConfig := func(setting, user string, active bool, certIDs ...string) {
		for _, id := range certIDs {
			if id == "" {
				continue
			}
			u.reference(id, user)
			if active {
				u.useByConfig(id, setting, setting == certSettingPinnedKeys)
			}
		}
	}

	tls := servesTLS(conf, specs)
	security := conf.Security

	addConfig(certSettingServer, serverCertsUser, tls, conf.HttpServerOptions.SSLCertificates...)
	for _, id := range security.Certificates.Upstream {
		addConfig(certSettingUpstream, gatewayConfigUser, true, id)
	}
	// The client CAs for all APIs are only read for APIs with client mTLS, during the TLS handshake.
	clientMTLS := slices.ContainsFunc(specs, func(spec *APISpec) bool {
		return spec.UseMutualTLSAuth && specServesTLS(conf, spec)
	})
	addConfig(certSettingAPIs, gatewayConfigUser, clientMTLS, security.Certificates.API...)
	// The control API takes the Gateway's protocol, so it only serves TLS when use_ssl is on.
	addConfig(certSettingControlAPI, gatewayConfigUser, conf.HttpServerOptions.UseSSL && security.ControlAPIUseMutualTLS, security.Certificates.ControlAPI...)
	for _, keys := range security.PinnedPublicKeys {
		// The Gateway splits pinned keys on "," without trimming them.
		addConfig(certSettingPinnedKeys, gatewayConfigUser, true, strings.Split(keys, ",")...)
	}

	// Named after their keys in external_services. The storage service isn't listed: the Gateway's
	// Redis connections read only its file-based mTLS settings.
	services := conf.ExternalServices
	for _, s := range []struct {
		name string
		mtls config.MTLSConfig
	}{
		{"oauth", services.OAuth.MTLS},
		{"webhooks", services.Webhooks.MTLS},
		{"health", services.Health.MTLS},
		{"discovery", services.Discovery.MTLS},
	} {
		setting := externalServiceCertSetting(s.name)
		addConfig(setting, gatewayConfigUser, s.mtls.Enabled, s.mtls.CertID)
		addConfig(setting, gatewayConfigUser, s.mtls.Enabled, s.mtls.CACertIDs...)
	}

	return u
}

// updateCertUsage rebuilds the certificates the Gateway uses from the loaded API specs and its configuration.
func (gw *Gateway) updateCertUsage(specs []*APISpec) {
	if gw.certUsageTracker == nil {
		return
	}
	conf := gw.GetConfig()
	gw.certUsageTracker.replace(collectCertUsage(&conf, specs))
}

// certificateReport returns the certificates the Gateway uses, as reported to the control plane.
func (gw *Gateway) certificateReport() []model.CertificateUsage {
	if gw.certUsageTracker == nil {
		return []model.CertificateUsage{}
	}
	return gw.certUsageTracker.Report()
}
