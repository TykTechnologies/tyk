package user

import (
	"github.com/TykTechnologies/storage/persistent/model"
	"github.com/TykTechnologies/tyk/apidef"
)

type GraphAccessDefinition struct{}

// Policy represents a user policy
// swagger:model
type Policy struct {
	MID                           model.ObjectID                   `bson:"_id,omitempty" json:"_id" gorm:"primaryKey;column:_id" example:"5ead7120575961000181867e"`
	ID                            string                           `bson:"id,omitempty" json:"id" example:"5ead7120575961000181867e"`
	Name                          string                           `bson:"name" json:"name" example:"Swagger Petstore Policy"`
	OrgID                         string                           `bson:"org_id" json:"org_id" example:"5e9d9544a1dcd60001d0ed20"`
	Rate                          float64                          `bson:"rate" json:"rate" format:"double" example:"1000"`
	Per                           float64                          `bson:"per" json:"per" format:"double" example:"60"`
	QuotaMax                      int64                            `bson:"quota_max" json:"quota_max" example:"-1" format:"int64"`
	QuotaRenewalRate              int64                            `bson:"quota_renewal_rate" json:"quota_renewal_rate" format:"int64" example:"3600"`
	ThrottleInterval              float64                          `bson:"throttle_interval" json:"throttle_interval" format:"double" example:"-1"`
	ThrottleRetryLimit            int                              `bson:"throttle_retry_limit" json:"throttle_retry_limit" example:"-1"`
	MaxQueryDepth                 int                              `bson:"max_query_depth" json:"max_query_depth" example:"-1"`
	AccessRights                  map[string]AccessDefinition      `bson:"access_rights" json:"access_rights"`
	HMACEnabled                   bool                             `bson:"hmac_enabled" json:"hmac_enabled" example:"false"`
	EnableHTTPSignatureValidation bool                             `json:"enable_http_signature_validation" msg:"enable_http_signature_validation" example:"false"`
	Active                        bool                             `bson:"active" json:"active" example:"true"`
	IsInactive                    bool                             `bson:"is_inactive" json:"is_inactive" example:"false"`
	Tags                          []string                         `bson:"tags" json:"tags"`
	KeyExpiresIn                  int64                            `bson:"key_expires_in" json:"key_expires_in" example:"0" format:"int64"`
	Partitions                    PolicyPartitions                 `bson:"partitions" json:"partitions"`
	LastUpdated                   string                           `bson:"last_updated" json:"last_updated" example:"1655965189"`
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
	Quota      bool `bson:"quota" json:"quota" example:"true"`
	RateLimit  bool `bson:"rate_limit" json:"rate_limit" example:"true"`
	Complexity bool `bson:"complexity" json:"complexity" example:"false"`
	Acl        bool `bson:"acl" json:"acl" example:"true"`
	PerAPI     bool `bson:"per_api" json:"per_api" example:"false"`
}

// Enabled reports if partitioning is enabled.
func (p PolicyPartitions) Enabled() bool {
	return p.Quota || p.RateLimit || p.Acl || p.Complexity
}
