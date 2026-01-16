package user

import (
	"crypto/md5"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/apidef"
)

type HashType string

const (
	HashPlainText HashType = ""
	HashBCrypt             = "bcrypt"
	HashSha256             = "sha256"
	HashMurmur32           = "murmur32"
	HashMurmur64           = "murmur64"
	HashMurmur128          = "murmur128"
)

func IsHashType(t string) bool {
	switch HashType(t) {
	case HashBCrypt, HashSha256, HashMurmur32, HashMurmur64, HashMurmur128:
		return true
	}
	return false
}

// AccessSpecs define what URLS a user has access to an what methods are enabled
type AccessSpec struct {
	URL     string   `json:"url" msg:"url"`
	Methods []string `json:"methods" msg:"methods"`
}

// RateLimit holds rate limit configuration.
type RateLimit struct {
	// Rate is the allowed number of requests per interval.
	Rate float64 `json:"rate,omitzero" msg:"rate"`
	// Per is the interval at which rate limit is enforced.
	Per float64 `json:"per,omitzero" msg:"per"`

	// Smoothing contains rate limit smoothing settings.
	Smoothing *apidef.RateLimitSmoothing `json:"smoothing,omitzero" bson:"smoothing,omitempty"`
}

// APILimit stores quota and rate limit on ACL level (per API)
type APILimit struct {
	RateLimit
	ThrottleInterval   float64 `json:"throttle_interval,omitzero" msg:"throttle_interval"`
	ThrottleRetryLimit int     `json:"throttle_retry_limit,omitzero" msg:"throttle_retry_limit"`
	MaxQueryDepth      int     `json:"max_query_depth,omitzero" msg:"max_query_depth"`
	QuotaMax           int64   `json:"quota_max,omitzero" msg:"quota_max"`
	QuotaRenews        int64   `json:"quota_renews,omitzero" msg:"quota_renews"`
	QuotaRemaining     int64   `json:"quota_remaining,omitzero" msg:"quota_remaining"`
	QuotaRenewalRate   int64   `json:"quota_renewal_rate,omitzero" msg:"quota_renewal_rate"`
	SetBy              string  `json:"-" msg:"-"`
}

// Clone does a deepcopy of APILimit.
func (a APILimit) Clone() *APILimit {
	var smoothingRef *apidef.RateLimitSmoothing
	if a.Smoothing != nil {
		smoothing := *a.Smoothing
		smoothingRef = &smoothing
	}

	return &APILimit{
		RateLimit: RateLimit{
			Rate:      a.Rate,
			Per:       a.Per,
			Smoothing: smoothingRef,
		},
		ThrottleInterval:   a.ThrottleInterval,
		ThrottleRetryLimit: a.ThrottleRetryLimit,
		MaxQueryDepth:      a.MaxQueryDepth,
		QuotaMax:           a.QuotaMax,
		QuotaRenews:        a.QuotaRenews,
		QuotaRemaining:     a.QuotaRemaining,
		QuotaRenewalRate:   a.QuotaRenewalRate,
		SetBy:              a.SetBy,
	}
}

// Duration returns the time between two allowed requests at the defined rate.
// It's used to decide which rate limit has a bigger allowance.
func (r RateLimit) Duration() time.Duration {
	if r.Per <= 0 || r.Rate <= 0 {
		return 0
	}
	return time.Duration(float64(time.Second) * r.Per / r.Rate)
}

// AccessDefinition defines which versions of an API a key has access to
// NOTE: when adding new fields it is required to map them from DBAccessDefinition
// in the gateway/policy.go:19
// TODO: is it possible to share fields?
type AccessDefinition struct {
	APIName              string                  `json:"api_name,omitzero" msg:"api_name"`
	APIID                string                  `json:"api_id,omitzero" msg:"api_id"`
	Versions             []string                `json:"versions,omitempty" msg:"versions"`
	AllowedURLs          []AccessSpec            `json:"allowed_urls,omitempty" bson:"allowed_urls" msg:"allowed_urls"` // mapped string MUST be a valid regex
	RestrictedTypes      []graphql.Type          `json:"restricted_types,omitempty" msg:"restricted_types"`
	AllowedTypes         []graphql.Type          `json:"allowed_types,omitempty" msg:"allowed_types"`
	Limit                APILimit                `json:"limit,omitzero" msg:"limit"`
	FieldAccessRights    []FieldAccessDefinition `json:"field_access_rights,omitempty" msg:"field_access_rights"`
	DisableIntrospection bool                    `json:"disable_introspection,omitzero" msg:"disable_introspection"`

	AllowanceScope string `json:"allowance_scope,omitzero" msg:"allowance_scope"`

	Endpoints Endpoints `json:"endpoints,omitzero" msg:"endpoints,omitempty"`
}

// IsEmpty checks if APILimit is empty.
func (a APILimit) IsEmpty() bool {
	if a.Rate != 0 {
		return false
	}

	if a.Per != 0 {
		return false
	}

	if a.ThrottleInterval != 0 {
		return false
	}

	if a.ThrottleRetryLimit != 0 {
		return false
	}

	if a.MaxQueryDepth != 0 {
		return false
	}

	if a.QuotaMax != 0 {
		return false
	}

	if a.QuotaRenews != 0 {
		return false
	}

	if a.QuotaRemaining != 0 {
		return false
	}

	if a.QuotaRenewalRate != 0 {
		return false
	}

	if a.SetBy != "" {
		return false
	}

	return true
}

// IsZero returns true if APILimit is empty (for omitzero support).
// This is an alias for IsEmpty() to satisfy the omitzero interface.
func (a APILimit) IsZero() bool {
	return a.IsEmpty()
}

// IsZero returns true if RateLimit is empty (for omitzero support).
func (r RateLimit) IsZero() bool {
	return r.Rate == 0 && r.Per == 0 && r.Smoothing == nil
}

// IsZero returns true if FieldLimits is empty (for omitzero support).
func (f FieldLimits) IsZero() bool {
	return f.MaxQueryDepth == 0
}

type FieldAccessDefinition struct {
	TypeName  string      `json:"type_name,omitzero" msg:"type_name"`
	FieldName string      `json:"field_name,omitzero" msg:"field_name"`
	Limits    FieldLimits `json:"limits,omitzero" msg:"limits"`
}

type FieldLimits struct {
	MaxQueryDepth int `json:"max_query_depth,omitzero" msg:"max_query_depth"`
}

type BasicAuthData struct {
	Password string   `json:"password,omitzero" msg:"password"`
	Hash     HashType `json:"hash_type,omitzero" msg:"hash_type"`
}

// IsZero returns true if BasicAuthData is empty (for omitzero support).
func (b BasicAuthData) IsZero() bool {
	return b.Password == "" && b.Hash == ""
}

type JWTData struct {
	Secret string `json:"secret,omitzero" msg:"secret"`
}

// IsZero returns true if JWTData is empty (for omitzero support).
func (j JWTData) IsZero() bool {
	return j.Secret == ""
}

type Monitor struct {
	TriggerLimits []float64 `json:"trigger_limits,omitempty" msg:"trigger_limits"`
}

// IsZero returns true if Monitor is empty (for omitzero support).
func (m Monitor) IsZero() bool {
	return len(m.TriggerLimits) == 0
}

// Endpoints is a collection of Endpoint.
type Endpoints []Endpoint

// Len is used to implement sort interface.
func (es Endpoints) Len() int {
	return len(es)
}

// Less is used to implement sort interface.
func (es Endpoints) Less(i, j int) bool {
	return es[i].Path < es[j].Path
}

// Swap is used to implement sort interface.
func (es Endpoints) Swap(i, j int) {
	es[i], es[j] = es[j], es[i]
}

// Endpoint holds the configuration for endpoint rate limiting.
type Endpoint struct {
	Path    string          `json:"path,omitempty" msg:"path"`
	Methods EndpointMethods `json:"methods,omitempty" msg:"methods"`
}

// EndpointMethods is a collection of EndpointMethod.
type EndpointMethods []EndpointMethod

// Len is used to implement sort interface.
func (em EndpointMethods) Len() int {
	return len(em)
}

// Less is used to implement sort interface.
func (em EndpointMethods) Less(i, j int) bool {
	return strings.ToUpper(em[i].Name) < strings.ToUpper(em[j].Name)
}

// Swap is used to implement sort interface.
func (em EndpointMethods) Swap(i, j int) {
	em[i], em[j] = em[j], em[i]
}

// Contains is used to assert if a method exists in EndpointMethods.
func (em EndpointMethods) Contains(method string) bool {
	for _, v := range em {
		if strings.EqualFold(v.Name, method) {
			return true
		}
	}
	return false
}

// EndpointMethod holds the configuration on endpoint method level.
type EndpointMethod struct {
	Name  string    `json:"name,omitempty" msg:"name,omitempty"`
	Limit RateLimit `json:"limit,omitempty" msg:"limit,omitempty"`
}

// SessionState objects represent a current API session, mainly used for rate limiting.
// There's a data structure that's based on this and it's used for Protocol Buffer support, make sure to update "coprocess/proto/coprocess_session_state.proto" and generate the bindings using: cd coprocess/proto && ./update_bindings.sh
//
// swagger:model
type SessionState struct {
	LastCheck                     int64                       `json:"last_check" msg:"last_check"`
	Allowance                     float64                     `json:"allowance" msg:"allowance"`
	Rate                          float64                     `json:"rate" msg:"rate"`
	Per                           float64                     `json:"per" msg:"per"`
	ThrottleInterval              float64                     `json:"throttle_interval" msg:"throttle_interval"`
	ThrottleRetryLimit            int                         `json:"throttle_retry_limit" msg:"throttle_retry_limit"`
	MaxQueryDepth                 int                         `json:"max_query_depth" msg:"max_query_depth"`
	DateCreated                   time.Time                   `json:"date_created" msg:"date_created"`
	Expires                       int64                       `json:"expires" msg:"expires"`
	QuotaMax                      int64                       `json:"quota_max" msg:"quota_max"`
	QuotaRenews                   int64                       `json:"quota_renews" msg:"quota_renews"`
	QuotaRemaining                int64                       `json:"quota_remaining" msg:"quota_remaining"`
	QuotaRenewalRate              int64                       `json:"quota_renewal_rate" msg:"quota_renewal_rate"`
	AccessRights                  map[string]AccessDefinition `json:"access_rights" msg:"access_rights"`
	OrgID                         string                      `json:"org_id" msg:"org_id"`
	OauthClientID                 string                      `json:"oauth_client_id" msg:"oauth_client_id"`
	OauthKeys                     map[string]string           `json:"oauth_keys" msg:"oauth_keys"`
	Certificate                   string                      `json:"certificate" msg:"certificate"`
	MtlsStaticCertificateBindings []string                    `json:"mtls_static_certificate_bindings" msg:"mtls_static_certificate_bindings"`
	BasicAuthData                 BasicAuthData               `json:"basic_auth_data" msg:"basic_auth_data"`
	JWTData                       JWTData                     `json:"jwt_data" msg:"jwt_data"`
	HMACEnabled                   bool                        `json:"hmac_enabled" msg:"hmac_enabled"`
	EnableHTTPSignatureValidation bool                        `json:"enable_http_signature_validation" msg:"enable_http_signature_validation"`
	HmacSecret                    string                      `json:"hmac_string" msg:"hmac_string"`
	RSACertificateId              string                      `json:"rsa_certificate_id" msg:"rsa_certificate_id"`
	IsInactive                    bool                        `json:"is_inactive" msg:"is_inactive"`
	ApplyPolicyID                 string                      `json:"apply_policy_id" msg:"apply_policy_id"`
	ApplyPolicies                 []string                    `json:"apply_policies" msg:"apply_policies"`
	DataExpires                   int64                       `json:"data_expires" msg:"data_expires"`
	Monitor                       Monitor                     `json:"monitor" msg:"monitor"`
	// Deprecated: EnableDetailRecording is deprecated. Use EnableDetailedRecording
	// going forward instead
	EnableDetailRecording   bool                   `json:"enable_detail_recording,omitzero" msg:"enable_detail_recording"`
	EnableDetailedRecording bool                   `json:"enable_detailed_recording,omitzero" msg:"enable_detailed_recording"`
	MetaData                map[string]interface{} `json:"meta_data,omitempty" msg:"meta_data"`
	Tags                    []string               `json:"tags,omitempty" msg:"tags"`
	Alias                   string                 `json:"alias,omitzero" msg:"alias"`
	LastUpdated             string                 `json:"last_updated,omitzero" msg:"last_updated"`
	IdExtractorDeadline     int64                  `json:"id_extractor_deadline,omitzero" msg:"id_extractor_deadline"`
	SessionLifetime         int64                  `json:"session_lifetime,omitzero" bson:"session_lifetime"`

	// Used to store token hash
	keyHash string
	KeyID   string `json:"-"`

	// Smoothing contains rate limit smoothing settings.
	Smoothing *apidef.RateLimitSmoothing `json:"smoothing,omitzero" bson:"smoothing"`

	// modified holds the hint if a session has been modified for update.
	// use Touch() to set it, and IsModified() to get it.
	modified bool
}

func NewSessionState() *SessionState {
	return &SessionState{}
}

// APILimit returns an user.APILimit from the session data.
func (s *SessionState) APILimit() APILimit {
	return APILimit{
		RateLimit: RateLimit{
			Rate:      s.Rate,
			Per:       s.Per,
			Smoothing: s.Smoothing,
		},
		QuotaMax:           s.QuotaMax,
		QuotaRenewalRate:   s.QuotaRenewalRate,
		QuotaRenews:        s.QuotaRenews,
		ThrottleInterval:   s.ThrottleInterval,
		ThrottleRetryLimit: s.ThrottleRetryLimit,
		MaxQueryDepth:      s.MaxQueryDepth,
	}
}

// Touch marks the session as modified, indicating that it should be updated.
func (s *SessionState) Touch() {
	s.modified = true
}

// Reset marks the session as not modified, skipping related updates.
func (s *SessionState) Reset() {
	s.modified = false
}

// IsModified will return true if session has been modified to trigger an update.
func (s *SessionState) IsModified() bool {
	return s.modified
}

// Clone  returns a fresh copy of s
func (s SessionState) Clone() SessionState {
	// Simple vales are cloned by value
	newSession := s
	newSession.AccessRights = cloneAccess(s.AccessRights)
	newSession.OauthKeys = cloneKeys(s.OauthKeys)
	newSession.ApplyPolicies = cloneSlice(s.ApplyPolicies)
	newSession.MetaData = cloneMetadata(s.MetaData)
	newSession.Tags = cloneSlice(s.Tags)

	return newSession
}

func cloneSlice(s []string) []string {
	if s == nil {
		return nil
	}
	if len(s) == 0 {
		return []string{}
	}
	x := make([]string, len(s))
	copy(x, s)
	return x
}

func cloneMetadata(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	if len(m) == 0 {
		return map[string]interface{}{}
	}
	x := make(map[string]interface{})
	for k, v := range m {
		x[k] = v
	}
	return x
}

func cloneKeys(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	if len(m) == 0 {
		return map[string]string{}
	}
	x := make(map[string]string)
	for k, v := range m {
		x[k] = v
	}
	return x
}
func cloneAccess(m map[string]AccessDefinition) map[string]AccessDefinition {
	if m == nil {
		return nil
	}
	if len(m) == 0 {
		return map[string]AccessDefinition{}
	}
	x := make(map[string]AccessDefinition)
	for k, v := range m {
		x[k] = v
	}
	return x
}

func (s *SessionState) MD5Hash() string {
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%+v", s))))
}

func (s *SessionState) KeyHash() string {
	if s.keyHash == "" {
		panic("KeyHash cache not found. You should call `SetKeyHash` before.")
	}

	return s.keyHash
}

func (s *SessionState) SetKeyHash(hash string) {
	s.keyHash = hash
}

func (s *SessionState) KeyHashEmpty() bool {
	return s.keyHash == ""
}

// Lifetime returns the lifetime of a session. Global session lifetime has always precedence. Then, the session lifetime value
// in the key level takes precedence. However, if key `respectKeyExpiration` is `true`, when the key expiration has longer than
// the session lifetime, the key expiration is returned. It means even if the session lifetime finishes, it waits for the key expiration
// for physical removal.
func (s *SessionState) Lifetime(respectKeyExpiration bool, fallback int64, forceGlobalSessionLifetime bool, globalSessionLifetime int64) int64 {
	if forceGlobalSessionLifetime {
		return globalSessionLifetime
	}

	if s.SessionLifetime > 0 {
		return calculateLifetime(respectKeyExpiration, s.Expires, s.SessionLifetime)
	}

	if fallback > 0 {
		return calculateLifetime(respectKeyExpiration, s.Expires, fallback)
	}

	return 0
}

// calculateLifetime calculates the lifetime of a session. It also sets the value to the key expiration in case of the key expiration
// value is respected and `lifetime` < `expiration`.
func calculateLifetime(respectExpiration bool, expiration, lifetime int64) int64 {
	if !respectExpiration || lifetime <= 0 {
		return lifetime
	}

	if expiration <= 0 {
		return expiration
	}

	now := time.Now()
	lifetimeInUnix := now.Add(time.Duration(lifetime) * time.Second).Unix()
	if expiration > lifetimeInUnix {
		return expiration - now.Unix()
	}

	return lifetime
}

// PolicyIDs returns the IDs of all the policies applied to this
// session. For backwards compatibility reasons, this falls back to
// ApplyPolicyID if ApplyPolicies is empty.
func (s *SessionState) PolicyIDs() []string {
	if len(s.ApplyPolicies) > 0 {
		return s.ApplyPolicies
	}
	if s.ApplyPolicyID != "" {
		return []string{s.ApplyPolicyID}
	}
	return nil
}

func (s *SessionState) SetPolicies(ids ...string) {
	s.ApplyPolicyID = ""
	s.ApplyPolicies = ids
}

// PoliciesEqualTo compares and returns true if passed slice if IDs contains only current ApplyPolicies
func (s *SessionState) PoliciesEqualTo(ids []string) bool {
	if len(s.ApplyPolicies) != len(ids) {
		return false
	}

	polIDMap := make(map[string]bool, len(ids))
	for _, id := range ids {
		polIDMap[id] = true
	}

	for _, curID := range s.ApplyPolicies {
		if !polIDMap[curID] {
			return false
		}
	}

	return true
}

// GetQuotaLimitByAPIID return quota max, quota remaining, quota renewal rate and quota renews for the given session
func (s *SessionState) GetQuotaLimitByAPIID(apiID string) (int64, int64, int64, int64) {
	if access, ok := s.AccessRights[apiID]; ok && !access.Limit.IsEmpty() {
		return access.Limit.QuotaMax,
			access.Limit.QuotaRemaining,
			access.Limit.QuotaRenewalRate,
			access.Limit.QuotaRenews
	}

	return s.QuotaMax, s.QuotaRemaining, s.QuotaRenewalRate, s.QuotaRenews
}

// IsBasicAuth returns whether the key is basic auth or not.
func (s *SessionState) IsBasicAuth() bool {
	return s.BasicAuthData.Password != ""
}

// EndpointRateLimitInfo holds the information to process endpoint rate limits.
type EndpointRateLimitInfo struct {
	// KeySuffix is the suffix to use for the storage key.
	KeySuffix string
	// Rate is the allowance.
	Rate float64
	// Per is the rate limiting interval.
	Per float64
}

// Map returns EndpointsMap of Endpoints using the key format [method:path].
// If duplicate entries are found, it would get overwritten with latest entries Endpoints.
func (es Endpoints) Map() EndpointsMap {
	if len(es) == 0 {
		return nil
	}

	out := make(EndpointsMap)
	for _, e := range es {
		for _, method := range e.Methods {
			key := fmt.Sprintf("%s:%s", method.Name, e.Path)
			out[key] = method.Limit
		}
	}

	return out
}

// EndpointsMap is the type to hold endpoint rate limit information as a map.
type EndpointsMap map[string]RateLimit

// Endpoints coverts EndpointsMap to Endpoints.
func (em EndpointsMap) Endpoints() Endpoints {
	if len(em) == 0 {
		return nil
	}

	var perPathMethods = make(map[string]EndpointMethods)
	for key, rateLimit := range em {
		keyParts := strings.Split(key, ":")
		if len(keyParts) != 2 {
			continue
		}

		method, path := keyParts[0], keyParts[1]
		epMethod := EndpointMethod{
			Name:  method,
			Limit: rateLimit,
		}
		if methods, ok := perPathMethods[path]; ok {
			perPathMethods[path] = append(methods, epMethod)
			continue
		}

		perPathMethods[path] = EndpointMethods{
			epMethod,
		}
	}

	var endpoints Endpoints
	for path, methods := range perPathMethods {
		sort.Sort(methods)
		endpoints = append(endpoints, Endpoint{
			Path:    path,
			Methods: methods,
		})
	}

	sort.Sort(endpoints)

	return endpoints
}
