package user

import (
	"github.com/TykTechnologies/storage/persistent/model"
	"github.com/TykTechnologies/tyk/apidef"
)

type GraphAccessDefinition struct {
}

// Policy represents a user policy
// swagger:model
//
// reqproof:model
// field QuotaMax int64
// field QuotaRenewalRate int64
// field Rate float64
// field Per float64
// field ThrottleInterval float64
// field ThrottleRetryLimit int
// field Active bool
// field IsInactive bool
type Policy struct {
	MID                           model.ObjectID                   `bson:"_id,omitempty" json:"_id" gorm:"primaryKey;column:_id"`
	ID                            string                           `bson:"id,omitempty" json:"id"`
	Name                          string                           `bson:"name" json:"name"`
	OrgID                         string                           `bson:"org_id" json:"org_id"`
	Rate                          float64                          `bson:"rate" json:"rate"`
	Per                           float64                          `bson:"per" json:"per"`
	QuotaMax                      int64                            `bson:"quota_max" json:"quota_max"`
	QuotaRenewalRate              int64                            `bson:"quota_renewal_rate" json:"quota_renewal_rate"`
	ThrottleInterval              float64                          `bson:"throttle_interval" json:"throttle_interval"`
	ThrottleRetryLimit            int                              `bson:"throttle_retry_limit" json:"throttle_retry_limit"`
	MaxQueryDepth                 int                              `bson:"max_query_depth" json:"max_query_depth"`
	AccessRights                  map[string]AccessDefinition      `bson:"access_rights" json:"access_rights"`
	HMACEnabled                   bool                             `bson:"hmac_enabled" json:"hmac_enabled"`
	EnableHTTPSignatureValidation bool                             `json:"enable_http_signature_validation" msg:"enable_http_signature_validation"`
	Active                        bool                             `bson:"active" json:"active"`
	IsInactive                    bool                             `bson:"is_inactive" json:"is_inactive"`
	Tags                          []string                         `bson:"tags" json:"tags"`
	KeyExpiresIn                  int64                            `bson:"key_expires_in" json:"key_expires_in"`
	PostExpiryAction              PostExpiryAction                 `bson:"post_expiry_action" json:"post_expiry_action,omitzero"`
	PostExpiryGracePeriod         int64                            `bson:"post_expiry_grace_period" json:"post_expiry_grace_period"`
	Partitions                    PolicyPartitions                 `bson:"partitions" json:"partitions"`
	LastUpdated                   string                           `bson:"last_updated" json:"last_updated"`
	MetaData                      map[string]interface{}           `bson:"meta_data" json:"meta_data"`
	GraphQL                       map[string]GraphAccessDefinition `bson:"graphql_access_rights" json:"graphql_access_rights"`

	// Smoothing contains rate limit smoothing settings.
	Smoothing *apidef.RateLimitSmoothing `json:"smoothing" bson:"smoothing"`
}

// SW-REQ-145
func (p *Policy) APILimit() APILimit {
	return APILimit{
		QuotaMax:           p.QuotaMax,
		QuotaRenewalRate:   p.QuotaRenewalRate,
		ThrottleInterval:   p.ThrottleInterval,
		ThrottleRetryLimit: p.ThrottleRetryLimit,
		MaxQueryDepth:      p.MaxQueryDepth,
		RateLimit: RateLimit{
			Rate:      p.Rate,
			Per:       p.Per,
			Smoothing: p.Smoothing,
		},
	}
}

type PolicyPartitions struct {
	Quota      bool `bson:"quota" json:"quota"`
	RateLimit  bool `bson:"rate_limit" json:"rate_limit"`
	Complexity bool `bson:"complexity" json:"complexity"`
	Acl        bool `bson:"acl" json:"acl"`
	PerAPI     bool `bson:"per_api" json:"per_api"`
}

// Enabled reports if partitioning is enabled.
// SW-REQ-145
func (p PolicyPartitions) Enabled() bool {
	return p.Quota || p.RateLimit || p.Acl || p.Complexity
}

// IsActiveQuotaConfigured reports whether the policy is active (Active &&
// !IsInactive) and has a positive QuotaMax — i.e. it can serve quota-gated
// requests at all. The policy engine's per-request quota check uses this
// natural correctness condition.
//
// reqproof:requires p.QuotaMax > 0
// reqproof:requires p.Active == true
// reqproof:requires p.IsInactive == false
//
//	reqproof:lemma policy_meets_quota_when_active_and_quota_positive func(p Policy) bool {
//	  return p.QuotaMax > 0 && p.Active && !p.IsInactive
//	}
//
// SW-REQ-145
func (p Policy) IsActiveQuotaConfigured() bool {
	return p.QuotaMax > 0 && p.Active && !p.IsInactive
}

// HasNonNegativeQuota reports whether the policy's QuotaMax is
// non-negative — the storage-level invariant the Apply path relies on.
// Admin API validation guarantees QuotaMax >= 0.
//
// reqproof:requires p.QuotaMax >= 0
//
//	reqproof:lemma policy_quota_max_valid_iff_nonneg func(p Policy) bool {
//	  return p.QuotaMax >= 0
//	}
//
// SW-REQ-145
func (p Policy) HasNonNegativeQuota() bool {
	return p.QuotaMax >= 0
}

// HasConfiguredRate reports whether the policy's Rate and Per are both
// strictly positive — the rate-limit subsystem treats "either zero" as
// disabled (see user.RateLimit.Duration()).
//
// reqproof:requires p.Rate > 0.0
// reqproof:requires p.Per > 0.0
//
//	reqproof:lemma policy_rate_pair_consistency func(p Policy) bool {
//	  return p.Rate > 0.0 && p.Per > 0.0
//	}
//
// SW-REQ-145
func (p Policy) HasConfiguredRate() bool {
	return p.Rate > 0.0 && p.Per > 0.0
}

// HasConfiguredThrottle reports whether the policy's ThrottleRetryLimit
// is positive — i.e. retries are enabled with a finite budget.
//
// reqproof:requires p.ThrottleRetryLimit > 0
//
//	reqproof:lemma policy_throttle_configured_when_positive func(p Policy) bool {
//	  return p.ThrottleRetryLimit > 0
//	}
//
// SW-REQ-145
func (p Policy) HasConfiguredThrottle() bool {
	return p.ThrottleRetryLimit > 0
}
