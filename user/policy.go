package user

import (
	"github.com/TykTechnologies/storage/persistent/model"
	"github.com/TykTechnologies/tyk/apidef"
)

type GraphAccessDefinition struct {
}

// Policy represents a user policy
// swagger:model
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
	Partitions                    PolicyPartitions                 `bson:"partitions" json:"partitions"`
	LastUpdated                   string                           `bson:"last_updated" json:"last_updated"`
	MetaData                      map[string]interface{}           `bson:"meta_data" json:"meta_data"`
	GraphQL                       map[string]GraphAccessDefinition `bson:"graphql_access_rights" json:"graphql_access_rights"`

	// Smoothing contains rate limit smoothing settings.
	Smoothing *apidef.RateLimitSmoothing `json:"smoothing" bson:"smoothing"`
}

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
func (p PolicyPartitions) Enabled() bool {
	return p.Quota || p.RateLimit || p.Acl || p.Complexity
}
