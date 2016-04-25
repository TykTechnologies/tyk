package main

type HashType string

const (
	HASH_PlainText HashType = ""
	HASH_BCrypt    HashType = "bcrypt"
)

// AccessSpecs define what URLS a user has access to an what methods are enabled
type AccessSpec struct {
	URL     string   `json:"url"`
	Methods []string `json:"methods"`
}

// AccessDefinition defines which versions of an API a key has access to
type AccessDefinition struct {
	APIName     string       `json:"api_name"`
	APIID       string       `json:"api_id"`
	Versions    []string     `json:"versions"`
	AllowedURLs []AccessSpec `bson:"allowed_urls"  json:"allowed_urls"` // mapped string MUST be a valid regex
}

// SessionState objects represent a current API session, mainly used for rate limiting.
type SessionState struct {
	LastCheck        int64                       `json:"last_check"`
	Allowance        float64                     `json:"allowance"`
	Rate             float64                     `json:"rate"`
	Per              float64                     `json:"per"`
	Expires          int64                       `json:"expires"`
	QuotaMax         int64                       `json:"quota_max"`
	QuotaRenews      int64                       `json:"quota_renews"`
	QuotaRemaining   int64                       `json:"quota_remaining"`
	QuotaRenewalRate int64                       `json:"quota_renewal_rate"`
	AccessRights     map[string]AccessDefinition `json:"access_rights"`
	OrgID            string                      `json:"org_id"`
	OauthClientID    string                      `json:"oauth_client_id"`
	OauthKeys        map[string]string           `json:"oauth_keys"`
	BasicAuthData    struct {
		Password string   `json:"password"`
		Hash     HashType `json:"hash_type"`
	} `json:"basic_auth_data"`
	JWTData struct {
		Secret string `json:"secret"`
	} `json:"jwt_data"`
	HMACEnabled   bool   `json:"hmac_enabled"`
	HmacSecret    string `json:"hmac_string"`
	IsInactive    bool   `json:"is_inactive"`
	ApplyPolicyID string `json:"apply_policy_id"`
	DataExpires   int64  `json:"data_expires"`
	Monitor       struct {
		TriggerLimits []float64 `json:"trigger_limits"`
	} `json:"monitor"`
	EnableDetailedRecording bool        `json:"enable_detail_recording"`
	MetaData                interface{} `json:"meta_data"`
	Tags                    []string    `json:"tags"`
	Alias string `json:"alias"`
}
