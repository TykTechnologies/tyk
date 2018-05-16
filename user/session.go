package user

import (
	"github.com/spaolacci/murmur3"
	"gopkg.in/vmihailenco/msgpack.v2"

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

// AccessDefinition defines which versions of an API a key has access to
type AccessDefinition struct {
	APIName     string       `json:"api_name" msg:"api_name"`
	APIID       string       `json:"api_id" msg:"api_id"`
	Versions    []string     `json:"versions" msg:"versions"`
	AllowedURLs []AccessSpec `bson:"allowed_urls"  json:"allowed_urls" msg:"allowed_urls"` // mapped string MUST be a valid regex
}

// SessionState objects represent a current API session, mainly used for rate limiting.
// There's a data structure that's based on this and it's used for Protocol Buffer support, make sure to update "coprocess/proto/coprocess_session_state.proto" and generate the bindings using: cd coprocess/proto && ./update_bindings.sh
type SessionState struct {
	LastCheck        int64                       `json:"last_check" msg:"last_check"`
	Allowance        float64                     `json:"allowance" msg:"allowance"`
	Rate             float64                     `json:"rate" msg:"rate"`
	Per              float64                     `json:"per" msg:"per"`
	Expires          int64                       `json:"expires" msg:"expires"`
	QuotaMax         int64                       `json:"quota_max" msg:"quota_max"`
	QuotaRenews      int64                       `json:"quota_renews" msg:"quota_renews"`
	QuotaRemaining   int64                       `json:"quota_remaining" msg:"quota_remaining"`
	QuotaRenewalRate int64                       `json:"quota_renewal_rate" msg:"quota_renewal_rate"`
	AccessRights     map[string]AccessDefinition `json:"access_rights" msg:"access_rights"`
	OrgID            string                      `json:"org_id" msg:"org_id"`
	OauthClientID    string                      `json:"oauth_client_id" msg:"oauth_client_id"`
	OauthKeys        map[string]string           `json:"oauth_keys" msg:"oauth_keys"`
	Certificate      string                      `json:"certificate" msg:"certificate"`
	BasicAuthData    struct {
		Password string   `json:"password" msg:"password"`
		Hash     HashType `json:"hash_type" msg:"hash_type"`
	} `json:"basic_auth_data" msg:"basic_auth_data"`
	JWTData struct {
		Secret string `json:"secret" msg:"secret"`
	} `json:"jwt_data" msg:"jwt_data"`
	HMACEnabled   bool     `json:"hmac_enabled" msg:"hmac_enabled"`
	HmacSecret    string   `json:"hmac_string" msg:"hmac_string"`
	IsInactive    bool     `json:"is_inactive" msg:"is_inactive"`
	ApplyPolicyID string   `json:"apply_policy_id" msg:"apply_policy_id"`
	ApplyPolicies []string `json:"apply_policies" msg:"apply_policies"`
	DataExpires   int64    `json:"data_expires" msg:"data_expires"`
	Monitor       struct {
		TriggerLimits []float64 `json:"trigger_limits" msg:"trigger_limits"`
	} `json:"monitor" msg:"monitor"`
	EnableDetailedRecording bool                   `json:"enable_detail_recording" msg:"enable_detail_recording"`
	MetaData                map[string]interface{} `json:"meta_data" msg:"meta_data"`
	Tags                    []string               `json:"tags" msg:"tags"`
	Alias                   string                 `json:"alias" msg:"alias"`
	LastUpdated             string                 `json:"last_updated" msg:"last_updated"`
	IdExtractorDeadline     int64                  `json:"id_extractor_deadline" msg:"id_extractor_deadline"`
	SessionLifetime         int64                  `bson:"session_lifetime" json:"session_lifetime"`

	firstSeenHash string
}

func (s *SessionState) SetFirstSeenHash() {
	s.firstSeenHash = s.Hash()
}

func (s *SessionState) Hash() string {
	encoded, err := msgpack.Marshal(s)
	if err != nil {
		log.Error("Error encoding session data: ", err)
		return ""
	}
	murmurHasher := murmur3.New32()
	murmurHasher.Write(encoded)
	murmurHasher.Sum32()
	return string(murmurHasher.Sum(nil)[:])
}

func (s *SessionState) HasChanged() bool {
	return s.firstSeenHash == "" || s.firstSeenHash != s.Hash()
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
