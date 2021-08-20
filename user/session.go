package user

import (
	"crypto/md5"
	"fmt"
	"time"

	"github.com/jensneuse/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/config"
	logger "github.com/TykTechnologies/tyk/log"
)

var log = logger.Get()

type HashType string

const (
	HashPlainText HashType = ""
	HashBCrypt    HashType = "bcrypt"
)

// AccessSpecs define what URLS a user has access to an what methods are enabled
type AccessSpec struct {
	URL     string   `json:"url" msg:"url"`
	Methods []string `json:"methods" msg:"methods"`
}

// APILimit stores quota and rate limit on ACL level (per API)
type APILimit struct {
	Rate               float64 `json:"rate" msg:"rate"`
	Per                float64 `json:"per" msg:"per"`
	ThrottleInterval   float64 `json:"throttle_interval" msg:"throttle_interval"`
	ThrottleRetryLimit int     `json:"throttle_retry_limit" msg:"throttle_retry_limit"`
	MaxQueryDepth      int     `json:"max_query_depth" msg:"max_query_depth"`
	QuotaMax           int64   `json:"quota_max" msg:"quota_max"`
	QuotaRenews        int64   `json:"quota_renews" msg:"quota_renews"`
	QuotaRemaining     int64   `json:"quota_remaining" msg:"quota_remaining"`
	QuotaRenewalRate   int64   `json:"quota_renewal_rate" msg:"quota_renewal_rate"`
	SetBy              string  `json:"-" msg:"-"`
}

// AccessDefinition defines which versions of an API a key has access to
// NOTE: when adding new fields it is required to map them from DBAccessDefinition
// in the gateway/policy.go:19
// TODO: is it possible to share fields?
type AccessDefinition struct {
	APIName           string                  `json:"api_name" msg:"api_name"`
	APIID             string                  `json:"api_id" msg:"api_id"`
	Versions          []string                `json:"versions" msg:"versions"`
	AllowedURLs       []AccessSpec            `bson:"allowed_urls" json:"allowed_urls" msg:"allowed_urls"` // mapped string MUST be a valid regex
	RestrictedTypes   []graphql.Type          `json:"restricted_types" msg:"restricted_types"`
	Limit             APILimit                `json:"limit" msg:"limit"`
	FieldAccessRights []FieldAccessDefinition `json:"field_access_rights" msg:"field_access_rights"`

	AllowanceScope string `json:"allowance_scope" msg:"allowance_scope"`
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
	TriggerLimits []float64 `json:"trigger_limits" msg:"trigger_limits"`
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
	EnableDetailRecording   bool                   `json:"enable_detail_recording" msg:"enable_detail_recording"`
	EnableDetailedRecording bool                   `json:"enable_detailed_recording" msg:"enable_detailed_recording"`
	MetaData                map[string]interface{} `json:"meta_data" msg:"meta_data"`
	Tags                    []string               `json:"tags" msg:"tags"`
	Alias                   string                 `json:"alias" msg:"alias"`
	LastUpdated             string                 `json:"last_updated" msg:"last_updated"`
	IdExtractorDeadline     int64                  `json:"id_extractor_deadline" msg:"id_extractor_deadline"`
	SessionLifetime         int64                  `bson:"session_lifetime" json:"session_lifetime"`

	// Used to store token hash
	keyHash string
	KeyID   string `json:"key_id,omitempty"`
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

func (s *SessionState) Lifetime(fallback int64) int64 {
	if config.Global().ForceGlobalSessionLifetime {
		return config.Global().GlobalSessionLifetime
	}
	if s.SessionLifetime > 0 {
		return s.SessionLifetime
	}
	if fallback > 0 {
		return fallback
	}
	return 0
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
