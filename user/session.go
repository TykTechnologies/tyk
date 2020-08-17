package user

import (
	"crypto/md5"
	"fmt"
	"sync"
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
type AccessDefinition struct {
	APIName         string         `json:"api_name" msg:"api_name"`
	APIID           string         `json:"api_id" msg:"api_id"`
	Versions        []string       `json:"versions" msg:"versions"`
	AllowedURLs     []AccessSpec   `bson:"allowed_urls" json:"allowed_urls" msg:"allowed_urls"` // mapped string MUST be a valid regex
	RestrictedTypes []graphql.Type `json:"restricted_types" msg:"restricted_types"`
	Limit           *APILimit      `json:"limit" msg:"limit"`

	AllowanceScope string `json:"allowance_scope" msg:"allowance_scope"`
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
	Mutex                         sync.RWMutex
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
}

func (s *SessionState) SetLastCheck(lastCheck int64) {
	s.Mutex.Lock()
	s.LastCheck = lastCheck
	s.Mutex.Unlock()
}

func (s *SessionState) SetAllowance(allowance float64) {
	s.Mutex.Lock()
	s.Allowance = allowance
	s.Mutex.Unlock()
}

func (s *SessionState) SetRate(rate float64) {
	s.Mutex.Lock()
	s.Rate = rate
	s.Mutex.Unlock()
}

func (s *SessionState) SetPer(per float64) {
	s.Mutex.Lock()
	s.Per = per
	s.Mutex.Unlock()
}

func (s *SessionState) SetThrottleInterval(throttleInterval float64) {
	s.Mutex.Lock()
	s.ThrottleInterval = throttleInterval
	s.Mutex.Unlock()
}

func (s *SessionState) SetThrottleRetryLimit(throttleRetryLimit int) {
	s.Mutex.Lock()
	s.ThrottleRetryLimit = throttleRetryLimit
	s.Mutex.Unlock()
}

func (s *SessionState) SetMaxQueryDepth(maxQueryDepth int) {
	s.Mutex.Lock()
	s.MaxQueryDepth = maxQueryDepth
	s.Mutex.Unlock()
}

func (s *SessionState) SetDateCreated(dateCreated time.Time) {
	s.Mutex.Lock()
	s.DateCreated = dateCreated
	s.Mutex.Unlock()
}

func (s *SessionState) SetExpires(expires int64) {
	s.Mutex.Lock()
	s.Expires = expires
	s.Mutex.Unlock()
}

func (s *SessionState) SetQuotaMax(quotaMax int64) {
	s.Mutex.Lock()
	s.QuotaMax = quotaMax
	s.Mutex.Unlock()
}

func (s *SessionState) SetQuotaRenews(quotaRenews int64) {
	s.Mutex.Lock()
	s.QuotaRenews = quotaRenews
	s.Mutex.Unlock()
}

func (s *SessionState) SetQuotaRemaining(quotaRemaining int64) {
	s.Mutex.Lock()
	s.QuotaRemaining = quotaRemaining
	s.Mutex.Unlock()
}

func (s *SessionState) SetQuotaRenewalRate(quotaRenewalRate int64) {
	s.Mutex.Lock()
	s.QuotaRenewalRate = quotaRenewalRate
	s.Mutex.Unlock()
}

func (s *SessionState) SetAccessRights(accessRights map[string]AccessDefinition) {
	s.Mutex.Lock()
	s.AccessRights = accessRights
	s.Mutex.Unlock()
}

func (s *SessionState) SetAccessRight(key string, accessRight AccessDefinition) {
	s.Mutex.Lock()
	s.AccessRights[key] = accessRight
	s.Mutex.Unlock()
}

func (s *SessionState) SetOrgID(orgId string) {
	s.Mutex.Lock()
	s.OrgID = orgId
	s.Mutex.Unlock()
}

func (s *SessionState) SetOauthClientID(oauthClientId string) {
	s.Mutex.Lock()
	s.OauthClientID = oauthClientId
	s.Mutex.Unlock()
}

func (s *SessionState) SetOauthKeys(oauthKeys map[string]string) {
	s.Mutex.Lock()
	s.OauthKeys = oauthKeys
	s.Mutex.Unlock()
}

func (s *SessionState) AppendOauthKey(key string, oauthKey string) {
	s.Mutex.Lock()
	s.OauthKeys[key] = oauthKey
	s.Mutex.Unlock()
}

func (s *SessionState) SetCertificate(certificate string) {
	s.Mutex.Lock()
	s.Certificate = certificate
	s.Mutex.Unlock()
}

func (s *SessionState) SetBasicAuthData(data BasicAuthData) {
	s.Mutex.Lock()
	s.BasicAuthData = data
	s.Mutex.Unlock()
}

func (s *SessionState) SetBasicAuthDataPassword(password string) {
	s.Mutex.Lock()
	s.BasicAuthData.Password = password
	s.Mutex.Unlock()
}

func (s *SessionState) SetBasicAuthDataHash(hash HashType) {
	s.Mutex.Lock()
	s.BasicAuthData.Hash = hash
	s.Mutex.Unlock()
}

func (s *SessionState) SetJWTData(jwtData JWTData) {
	s.Mutex.Lock()
	s.JWTData = jwtData
	s.Mutex.Unlock()
}

func (s *SessionState) SetHMACEnabled(hmacEnabled bool) {
	s.Mutex.Lock()
	s.HMACEnabled = hmacEnabled
	s.Mutex.Unlock()
}

func (s *SessionState) SetEnableHTTPSignatureValidation(enableHttpSignatureValidation bool) {
	s.Mutex.Lock()
	s.EnableHTTPSignatureValidation = enableHttpSignatureValidation
	s.Mutex.Unlock()
}

func (s *SessionState) SetHmacSecret(hmacSecret string) {
	s.Mutex.Lock()
	s.HmacSecret = hmacSecret
	s.Mutex.Unlock()
}

func (s *SessionState) SetRSACertificateId(rsaCertificateId string) {
	s.Mutex.Lock()
	s.RSACertificateId = rsaCertificateId
	s.Mutex.Unlock()
}

func (s *SessionState) SetIsInactive(isInactive bool) {
	s.Mutex.Lock()
	s.IsInactive = isInactive
	s.Mutex.Unlock()
}

func (s *SessionState) SetApplyPolicyID(applyPolicyId string) {
	s.Mutex.Lock()
	s.ApplyPolicyID = applyPolicyId
	s.Mutex.Unlock()
}

func (s *SessionState) SetApplyPolicies(applyPolicies []string) {
	s.Mutex.Lock()
	s.ApplyPolicies = applyPolicies
	s.Mutex.Unlock()
}

func (s *SessionState) SetDataExpires(dataExpires int64) {
	s.Mutex.Lock()
	s.DataExpires = dataExpires
	s.Mutex.Unlock()
}

func (s *SessionState) SetMonitor(monitor Monitor) {
	s.Mutex.Lock()
	s.Monitor = monitor
	s.Mutex.Unlock()
}

func (s *SessionState) SetEnableDetailRecording(enableDetailRecording bool) {
	s.Mutex.Lock()
	s.EnableDetailRecording = enableDetailRecording
	s.Mutex.Unlock()
}

func (s *SessionState) SetEnableDetailedRecording(enableDetailedRecording bool) {
	s.Mutex.Lock()
	s.EnableDetailedRecording = enableDetailedRecording
	s.Mutex.Unlock()
}

func (s *SessionState) SetMetaData(metadata map[string]interface{}) {
	s.Mutex.Lock()
	s.MetaData = metadata
	s.Mutex.Unlock()
}

func (s *SessionState) AppendMetaData(key string, metadata interface{}) {
	s.Mutex.Lock()
	s.MetaData[key] = metadata
	s.Mutex.Unlock()
}

func (s *SessionState) RemoveMetaData(key string) {
	s.Mutex.Lock()
	delete(s.MetaData, key)
	s.Mutex.Unlock()
}

func (s *SessionState) SetTags(tags []string) {
	s.Mutex.Lock()
	s.Tags = tags
	s.Mutex.Unlock()
}

func (s *SessionState) SetAlias(alias string) {
	s.Mutex.Lock()
	s.Alias = alias
	s.Mutex.Unlock()
}

func (s *SessionState) SetLastUpdated(lastUpdated string) {
	s.Mutex.Lock()
	s.LastUpdated = lastUpdated
	s.Mutex.Unlock()
}

func (s *SessionState) SetIdExtractorDeadline(idExtractorDeadline int64) {
	s.Mutex.Lock()
	s.IdExtractorDeadline = idExtractorDeadline
	s.Mutex.Unlock()
}

func (s *SessionState) SetSessionLifetime(sessionLifetime int64) {
	s.Mutex.Lock()
	s.SessionLifetime = sessionLifetime
	s.Mutex.Unlock()
}

func (s *SessionState) SetKeyHash(hash string) {
	s.Mutex.Lock()
	s.keyHash = hash
	s.Mutex.Unlock()
}

func (s *SessionState) KeyHashEmpty() bool {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.keyHash == ""
}

func (s *SessionState) Lifetime(fallback int64) int64 {
	if config.Global().ForceGlobalSessionLifetime {
		return config.Global().GlobalSessionLifetime
	}
	if s.SessionLifetime > 0 {
		s.Mutex.RLock()
		defer s.Mutex.RUnlock()
		return s.SessionLifetime
	}
	if fallback > 0 {
		return fallback
	}
	return 0
}

func (s *SessionState) GetLastCheck() (lastCheck int64) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.LastCheck
}

func (s *SessionState) GetAllowance() (allowance float64) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.Allowance
}

func (s *SessionState) GetRate() (rate float64) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.Rate
}

func (s *SessionState) GetPer() (per float64) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.Per
}

func (s *SessionState) GetThrottleInterval() (throttleInterval float64) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.ThrottleInterval
}

func (s *SessionState) GetThrottleRetryLimit() (throttleRetryLimit int) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.ThrottleRetryLimit
}

func (s *SessionState) GetMaxQueryDepth() (maxQueryDepth int) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.MaxQueryDepth
}

func (s *SessionState) GetDateCreated() (dateCreated time.Time) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.DateCreated
}

func (s *SessionState) GetExpires() (expires int64) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.Expires
}

func (s *SessionState) GetQuotaMax() (quotaMax int64) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.QuotaMax
}

func (s *SessionState) GetQuotaRenews() (quotaRenews int64) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.QuotaRenews
}

func (s *SessionState) GetQuotaRemaining() (quotaRemaining int64) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.QuotaRemaining
}

func (s *SessionState) GetQuotaRenewalRate() (renewalRate int64) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.QuotaRenewalRate
}

func (s *SessionState) GetAccessRights() (AccessRights map[string]AccessDefinition) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.AccessRights
}

func (s *SessionState) GetAccessRightByAPIID(key string) (AccessRight AccessDefinition, found bool) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	accessRight, found := s.AccessRights[key]
	return accessRight, found
}

func (s *SessionState) GetOrgID() (orgId string) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.OrgID
}

func (s *SessionState) GetOauthClientID() (oauthClientID string) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.OauthClientID
}

func (s *SessionState) GetOauthKeys() (oauthKeys map[string]string) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.OauthKeys
}

func (s *SessionState) GetCertificate() (certificate string) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.Certificate
}

func (s *SessionState) GetBasicAuthData() (basicAuthData BasicAuthData) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.BasicAuthData
}

func (s *SessionState) GetJWTData() (jwtData JWTData) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.JWTData
}

func (s *SessionState) GetHMACEnabled() (hmacEnabled bool) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.HMACEnabled
}

func (s *SessionState) GetEnableHTTPSignatureValidation() (enableHTTPSignatureValidation bool) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.EnableHTTPSignatureValidation
}

func (s *SessionState) GetHmacSecret() (hmacSecret string) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.HmacSecret
}

func (s *SessionState) GetRSACertificateId() (rsaCertificateId string) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.RSACertificateId
}

func (s *SessionState) GetIsInactive() (isInactive bool) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.IsInactive
}

// PolicyIDs returns the IDs of all the policies applied to this
// session. For backwards compatibility reasons, this falls back to
// ApplyPolicyID if ApplyPolicies is empty.
func (s *SessionState) GetPolicyIDs() []string {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()

	if len(s.ApplyPolicies) > 0 {
		return s.ApplyPolicies
	}
	if s.ApplyPolicyID != "" {
		return []string{s.ApplyPolicyID}
	}
	return nil
}

func (s *SessionState) GetApplyPolicies() (policies []string) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.ApplyPolicies
}

func (s *SessionState) GetApplyPolicyID() (policy string) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.ApplyPolicyID
}

func (s *SessionState) GetDataExpires() (dataExpires int64) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.DataExpires
}

func (s *SessionState) GetMonitor() (monitor Monitor) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.Monitor
}

// Deprecated: EnableDetailedRecording is deprecated
func (s *SessionState) GetEnableDetailRecording() (enableDetailRecording bool) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.EnableDetailRecording
}

func (s *SessionState) GetEnableDetailedRecording() (enableDetailedRecording bool) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.EnableDetailedRecording
}

func (s *SessionState) GetMetaData() (metaData map[string]interface{}) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.MetaData
}

func (s *SessionState) GetMetaDataByKey(key string) (metaData interface{}, found bool) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	value, ok := s.MetaData[key]
	return value, ok
}

func (s *SessionState) GetTags() (tags []string) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.Tags
}

func (s *SessionState) GetAlias() (alias string) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.Alias
}

func (s *SessionState) GetLastUpdated() (lastUpdated string) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.LastUpdated
}

func (s *SessionState) GetIdExtractorDeadline() (idExtractorDeadline int64) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.IdExtractorDeadline
}

func (s *SessionState) GetSessionLifetime() (sessionLifeTime int64) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return s.SessionLifetime
}

func (s *SessionState) MD5Hash() string {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%+v", s))))
}

func (s *SessionState) GetKeyHash() string {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	if s.keyHash == "" {
		panic("KeyHash cache not found. You should call `SetKeyHash` before.")
	}

	return s.keyHash
}

func (s *SessionState) SetPolicies(ids ...string) {
	s.Mutex.Lock()
	s.ApplyPolicyID = ""
	s.ApplyPolicies = ids
	s.Mutex.Unlock()
}

// PoliciesEqualTo compares and returns true if passed slice if IDs contains only current ApplyPolicies
func (s *SessionState) PoliciesEqualTo(ids []string) bool {

	s.Mutex.RLock()
	policies := s.ApplyPolicies
	s.Mutex.RUnlock()

	if len(policies) != len(ids) {
		return false
	}

	polIDMap := make(map[string]bool, len(ids))
	for _, id := range ids {
		polIDMap[id] = true
	}

	for _, curID := range policies {
		if !polIDMap[curID] {
			return false
		}
	}

	return true
}

// GetQuotaLimitByAPIID return quota max, quota remaining, quota renewal rate and quota renews for the given session
func (s *SessionState) GetQuotaLimitByAPIID(apiID string) (int64, int64, int64, int64) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()

	if access, ok := s.AccessRights[apiID]; ok && access.Limit != nil {
		return access.Limit.QuotaMax,
			access.Limit.QuotaRemaining,
			access.Limit.QuotaRenewalRate,
			access.Limit.QuotaRenews
	}

	return s.QuotaMax, s.QuotaRemaining, s.QuotaRenewalRate, s.QuotaRenews
}
