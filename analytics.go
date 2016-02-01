package main

import (
	"gopkg.in/vmihailenco/msgpack.v2"
	"time"
)

// AnalyticsRecord encodes the details of a request
type AnalyticsRecord struct {
	Method        string
	Path          string
	ContentLength int64
	UserAgent     string
	Day           int
	Month         time.Month
	Year          int
	Hour          int
	ResponseCode  int
	APIKey        string
	TimeStamp     time.Time
	APIVersion    string
	APIName       string
	APIID         string
	OrgID         string
	OauthID       string
	RequestTime   int64
	RawRequest    string
	RawResponse   string
	Tags          []string
	ExpireAt      time.Time `bson:"expireAt" json:"expireAt"`
}

const (
	ANALYTICS_KEYNAME string = "tyk-system-analytics"
)

func (a *AnalyticsRecord) SetExpiry(expiresInSeconds int64) {
	var expiry time.Duration

	expiry = time.Duration(expiresInSeconds) * time.Second

	if expiresInSeconds == 0 {
		// Expiry is set to 100 years
		expiry = (24 * time.Hour) * (365 * 100)
	}

	t := time.Now()
	t2 := t.Add(expiry)
	a.ExpireAt = t2
}

// AnalyticsError is an error for when writing to the storage engine fails
type AnalyticsError struct{}

func (e AnalyticsError) Error() string {
	return "Recording request failed!"
}

// AnalyticsHandler is an interface to record analytics data to a writer.
type AnalyticsHandler interface {
	RecordHit(AnalyticsRecord) error
}

// RedisAnalyticsHandler implements AnalyticsHandler and will record analytics
// data to a redis back end as defined in the Config object
type RedisAnalyticsHandler struct {
	Store *RedisClusterStorageManager
}

// RecordHit will store an AnalyticsRecord in Redis
func (r RedisAnalyticsHandler) RecordHit(thisRecord AnalyticsRecord) error {
	// If we are obfuscating API Keys, store the hashed representation (config check handled in hashing function)
	thisRecord.APIKey = publicHash(thisRecord.APIKey)

	if config.SlaveOptions.UseRPC {
		// Extend tag list to include this data so wecan segment by node if necessary
		thisRecord.Tags = append(thisRecord.Tags, "tyk-hybrid-rpc")
	}

	if config.DBAppConfOptions.NodeIsSegmented {
		// Extend tag list to include this data so wecan segment by node if necessary
		thisRecord.Tags = append(thisRecord.Tags, config.DBAppConfOptions.Tags...)
	}

	// Lets add some metadata
	if thisRecord.APIKey != "" {
		thisRecord.Tags = append(thisRecord.Tags, "key-"+thisRecord.APIKey)
	}

	if thisRecord.OrgID != "" {
		thisRecord.Tags = append(thisRecord.Tags, "org-"+thisRecord.OrgID)
	}

	thisRecord.Tags = append(thisRecord.Tags, "api-"+thisRecord.APIID)

	encoded, err := msgpack.Marshal(thisRecord)

	if err != nil {
		log.Error("Error encoding analytics data:")
		log.Error(err)
		return AnalyticsError{}
	}

	r.Store.AppendToSet(ANALYTICS_KEYNAME, string(encoded))

	return nil
}
