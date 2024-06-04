package user

import (
	"crypto/md5"
	"fmt"
	"time"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	logger "github.com/TykTechnologies/tyk/log"
)

var log = logger.Get()

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
	URL     string   `json:"url" msg:"url" example:"anything/rate-limit-1-per-5"`
	Methods []string `json:"methods" msg:"methods" example:"[\"GET\",\"POST\",\"DELETE\",\"PUT\"]"`
}

// APILimit stores quota and rate limit on ACL level (per API)
type APILimit struct {
	Rate               float64 `json:"rate" msg:"rate" example:"1" format:"double"`
	Per                float64 `json:"per" msg:"per" example:"5" format:"double"`
	ThrottleInterval   float64 `json:"throttle_interval" msg:"throttle_interval" example:"10" format:"double"`
	ThrottleRetryLimit int     `json:"throttle_retry_limit" msg:"throttle_retry_limit" example:"1000"`
	MaxQueryDepth      int     `json:"max_query_depth" msg:"max_query_depth" example:"-1"`
	QuotaMax           int64   `json:"quota_max" msg:"quota_max" example:"20000" format:"int64"`
	QuotaRenews        int64   `json:"quota_renews" msg:"quota_renews" example:"0" format:"int64"`
	QuotaRemaining     int64   `json:"quota_remaining" msg:"quota_remaining" example:"20000" format:"int64"`
	QuotaRenewalRate   int64   `json:"quota_renewal_rate" msg:"quota_renewal_rate" example:"2592000" format:"int64"`
	SetBy              string  `json:"-" msg:"-"`
}

// AccessDefinition defines which versions of an API a key has access to
// NOTE: when adding new fields it is required to map them from DBAccessDefinition
// in the gateway/policy.go:19
// TODO: is it possible to share fields?
type AccessDefinition struct {
	APIName              string                  `json:"api_name" msg:"api_name" example:"Rate Limit Proxy API"`
	APIID                string                  `json:"api_id" msg:"api_id" example:"d1dfc6a927a046c54c0ed470f19757cc"`
	Versions             []string                `json:"versions" msg:"versions" example:"[\"Default\",\"v2\"]"`
	AllowedURLs          []AccessSpec            `bson:"allowed_urls" json:"allowed_urls" msg:"allowed_urls"` // mapped string MUST be a valid regex
	RestrictedTypes      []graphql.Type          `json:"restricted_types" msg:"restricted_types"`
	AllowedTypes         []graphql.Type          `json:"allowed_types" msg:"allowed_types"`
	Limit                APILimit                `json:"limit" msg:"limit"`
	FieldAccessRights    []FieldAccessDefinition `json:"field_access_rights" msg:"field_access_rights"`
	DisableIntrospection bool                    `json:"disable_introspection" msg:"disable_introspection" example:"false"`

	AllowanceScope string `json:"allowance_scope" msg:"allowance_scope" example:"d371b83b249845a2497ab9a947fd6210"`
}

func (limit APILimit) IsEmpty() bool {
	if limit.Rate != 0 || limit.Per != 0 || limit.ThrottleInterval != 0 || limit.ThrottleRetryLimit != 0 || limit.MaxQueryDepth != 0 || limit.QuotaMax != 0 || limit.QuotaRenews != 0 || limit.QuotaRemaining != 0 || limit.QuotaRenewalRate != 0 || limit.SetBy != "" {
		return false
	}
	return true
}

type FieldAccessDefinition struct {
	TypeName  string      `json:"type_name" msg:"type_name"`
	FieldName string      `json:"field_name" msg:"field_name"`
	Limits    FieldLimits `json:"limits" msg:"limits"`
}

type FieldLimits struct {
	MaxQueryDepth int `json:"max_query_depth" msg:"max_query_depth"`
}

type BasicAuthData struct {
	Password string   `json:"password" msg:"password"`
	Hash     HashType `json:"hash_type" msg:"hash_type"`
}

type JWTData struct {
	Secret string `json:"secret" msg:"secret"`
}

type Monitor struct {
	TriggerLimits []float64 `json:"trigger_limits" msg:"trigger_limits" example:"[80, 60, 50]"`
}

// SessionState objects represent a current API session, mainly used for rate limiting.
// There's a data structure that's based on this and it's used for Protocol Buffer support, make sure to update "coprocess/proto/coprocess_session_state.proto" and generate the bindings using: cd coprocess/proto && ./update_bindings.sh
//
// swagger:model
type SessionState struct {
	LastCheck                     int64                       `json:"last_check" msg:"last_check" format:"int64" example:"0"`
	Allowance                     float64                     `json:"allowance" msg:"allowance" example:"1000" format:"double"`
	Rate                          float64                     `json:"rate" msg:"rate" format:"double" example:"1"`
	Per                           float64                     `json:"per" msg:"per" format:"double" example:"5"`
	ThrottleInterval              float64                     `json:"throttle_interval" msg:"throttle_interval" format:"double" example:"10"`
	ThrottleRetryLimit            int                         `json:"throttle_retry_limit" msg:"throttle_retry_limit" example:"1000"`
	MaxQueryDepth                 int                         `json:"max_query_depth" msg:"max_query_depth" example:"-1"`
	DateCreated                   time.Time                   `json:"date_created" msg:"date_created" example:"2024-03-13T03:56:46.568042549Z"`
	Expires                       int64                       `json:"expires" msg:"expires" example:"1712895619" format:"int64"`
	QuotaMax                      int64                       `json:"quota_max" msg:"quota_max" format:"int64" example:"20000"`
	QuotaRenews                   int64                       `json:"quota_renews" msg:"quota_renews" example:"1710302205" format:"int64"`
	QuotaRemaining                int64                       `json:"quota_remaining" msg:"quota_remaining" format:"int64" example:"20000"`
	QuotaRenewalRate              int64                       `json:"quota_renewal_rate" msg:"quota_renewal_rate" format:"int64" example:"31556952"`
	AccessRights                  map[string]AccessDefinition `json:"access_rights" msg:"access_rights"`
	OrgID                         string                      `json:"org_id" msg:"org_id" example:"5e9d9544a1dcd60001d0ed20"`
	OauthClientID                 string                      `json:"oauth_client_id" msg:"oauth_client_id"`
	OauthKeys                     map[string]string           `json:"oauth_keys" msg:"oauth_keys"`
	Certificate                   string                      `json:"certificate" msg:"certificate"`
	BasicAuthData                 BasicAuthData               `json:"basic_auth_data" msg:"basic_auth_data"`
	JWTData                       JWTData                     `json:"jwt_data" msg:"jwt_data"`
	HMACEnabled                   bool                        `json:"hmac_enabled" msg:"hmac_enabled" example:"false"`
	EnableHTTPSignatureValidation bool                        `json:"enable_http_signature_validation" msg:"enable_http_signature_validation" example:"false"`
	HmacSecret                    string                      `json:"hmac_string" msg:"hmac_string"`
	RSACertificateId              string                      `json:"rsa_certificate_id" msg:"rsa_certificate_id"`
	IsInactive                    bool                        `json:"is_inactive" msg:"is_inactive" example:"false"`
	ApplyPolicyID                 string                      `json:"apply_policy_id" msg:"apply_policy_id" example:"641c15dd0fffb800010197bf" deprecated:"true" description:"deprecated use apply_policies going forward instead to send a list of policies ids"`
	ApplyPolicies                 []string                    `json:"apply_policies" msg:"apply_policies" example:"[\"641c15dd0fffb800010197bf\"]"`
	DataExpires                   int64                       `json:"data_expires" msg:"data_expires" format:"int64" example:"0"`
	Monitor                       Monitor                     `json:"monitor" msg:"monitor"`
	// Deprecated: EnableDetailRecording is deprecated. Use EnableDetailedRecording
	// going forward instead
	EnableDetailRecording   bool                   `json:"enable_detail_recording" msg:"enable_detail_recording" example:"false" deprecated:"true" description:"deprecated use enable_detailed_recording going forward instead"`
	EnableDetailedRecording bool                   `json:"enable_detailed_recording" msg:"enable_detailed_recording" example:"true"`
	MetaData                map[string]interface{} `json:"meta_data" msg:"meta_data" example:"{\"tyk_developer_id\": \"62b3fb9a1d5e4f00017226f5\"}"`
	Tags                    []string               `json:"tags" msg:"tags" example:"[edge,edge-eu]"`
	Alias                   string                 `json:"alias" msg:"alias" example:"portal-developer@example.org"`
	LastUpdated             string                 `json:"last_updated" msg:"last_updated" example:"1710302206"`
	IdExtractorDeadline     int64                  `json:"id_extractor_deadline" msg:"id_extractor_deadline" format:"int64"`
	SessionLifetime         int64                  `bson:"session_lifetime" json:"session_lifetime" format:"int64" example:"0"`

	// Used to store token hash
	keyHash string
	KeyID   string `json:"-"`
}

func NewSessionState() *SessionState {
	return &SessionState{}
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
