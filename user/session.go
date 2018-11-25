package user

import (
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
	URL     string   `json:"url,omitempty" msg:"url"`
	Methods []string `json:"methods,omitempty" msg:"methods"`
}

// APILimit stores quota and rate limit on ACL level (per API)
type APILimit struct {
	Rate             float64 `json:"rate,omitempty" msg:"rate"`
	Per              float64 `json:"per,omitempty" msg:"per"`
	QuotaMax         int64   `json:"quota_max,omitempty" msg:"quota_max"`
	QuotaRenews      int64   `json:"quota_renews,omitempty" msg:"quota_renews"`
	QuotaRemaining   int64   `json:"quota_remaining,omitempty" msg:"quota_remaining"`
	QuotaRenewalRate int64   `json:"quota_renewal_rate,omitempty" msg:"quota_renewal_rate"`
	SetByPolicy      bool    `json:"set_by_policy,omitempty" msg:"set_by_policy"`
}

// AccessDefinition defines which versions of an API a key has access to
type AccessDefinition struct {
	APIName     string       `json:"api_name" msg:"api_name"`
	APIID       string       `json:"api_id" msg:"api_id"`
	Versions    []string     `json:"versions" msg:"versions"`
	AllowedURLs []AccessSpec `bson:"allowed_urls,omitempty" json:"allowed_urls" msg:"allowed_urls"` // mapped string MUST be a valid regex
	Limit       *APILimit    `json:"limit,omitempty" msg:"limit"`
}

// SessionState objects represent a current API session, mainly used for rate limiting.
// There's a data structure that's based on this and it's used for Protocol Buffer support, make sure to update "coprocess/proto/coprocess_session_state.proto" and generate the bindings using: cd coprocess/proto && ./update_bindings.sh
type SessionState struct {
	LastCheck        int64                       `json:"last_check,omitempty" msg:"last_check"`
	Allowance        float64                     `json:"allowance" msg:"allowance"`
	Rate             float64                     `json:"rate" msg:"rate"`
	Per              float64                     `json:"per" msg:"per"`
	Expires          int64                       `json:"expires,omitempty" msg:"expires"`
	QuotaMax         int64                       `json:"quota_max" msg:"quota_max"`
	QuotaRenews      int64                       `json:"quota_renews" msg:"quota_renews"`
	QuotaRemaining   int64                       `json:"quota_remaining" msg:"quota_remaining"`
	QuotaRenewalRate int64                       `json:"quota_renewal_rate" msg:"quota_renewal_rate"`
	AccessRights     map[string]AccessDefinition `json:"access_rights" msg:"access_rights"`
	OrgID            string                      `json:"org_id" msg:"org_id"`
	OauthClientID    string                      `json:"oauth_client_id,omitempty" msg:"oauth_client_id"`
	OauthKeys        map[string]string           `json:"oauth_keys,omitempty" msg:"oauth_keys"`
	Certificate      string                      `json:"certificate,omitempty" msg:"certificate"`
	BasicAuthData    struct {
		Password string   `json:"password" msg:"password"`
		Hash     HashType `json:"hash_type" msg:"hash_type"`
	} `json:"basic_auth_data,omitempty" msg:"basic_auth_data"`
	JWTData struct {
		Secret string `json:"secret" msg:"secret"`
	} `json:"jwt_data,omitempty" msg:"jwt_data"`
	HMACEnabled   bool     `json:"hmac_enabled,omitempty" msg:"hmac_enabled"`
	HmacSecret    string   `json:"hmac_string,omitempty" msg:"hmac_string"`
	IsInactive    bool     `json:"is_inactive,omitempty" msg:"is_inactive"`
	ApplyPolicyID string   `json:"apply_policy_id,omitempty" msg:"apply_policy_id"`
	ApplyPolicies []string `json:"apply_policies,omitempty" msg:"apply_policies"`
	DataExpires   int64    `json:"data_expires,omitempty" msg:"data_expires"`
	Monitor       struct {
		TriggerLimits []float64 `json:"trigger_limits" msg:"trigger_limits"`
	} `json:"monitor" msg:"monitor"`
	EnableDetailedRecording bool                   `json:"enable_detail_recording,omitempty" msg:"enable_detail_recording"`
	MetaData                map[string]interface{} `json:"meta_data,omitempty" msg:"meta_data"`
	Tags                    []string               `json:"tags,omitempty" msg:"tags"`
	Alias                   string                 `json:"alias,omitempty" msg:"alias"`
	LastUpdated             string                 `json:"last_updated,omitempty" msg:"last_updated"`
	IdExtractorDeadline     int64                  `json:"id_extractor_deadline,omitempty" msg:"id_extractor_deadline"`
	SessionLifetime         int64                  `bson:"session_lifetime,omitempty" json:"session_lifetime"`

	// Used to store token hash
	keyHash string
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
