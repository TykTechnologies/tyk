package analytics

import (
	"github.com/TykTechnologies/tyk/config"
	logger "github.com/TykTechnologies/tyk/log"
	"sync/atomic"
	"time"
)

var log = logger.Get()

// AnalyticsRecord encodes the details of a request
type Record struct {
	Method        string
	Host          string
	Path          string // HTTP path, can be overriden by "track path" plugin
	RawPath       string // Original HTTP path
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
	Latency       Latency
	RawRequest    string // Base64 encoded request data (if detailed recording turned on)
	RawResponse   string // ^ same but for response
	IPAddress     string
	Geo           GeoData
	Network       NetworkStats
	Tags          []string
	Alias         string
	TrackPath     bool
	ExpireAt      time.Time `bson:"expireAt" json:"expireAt"`
}

type Latency struct {
	Total    int64
	Upstream int64
}

type NetworkStats struct {
	OpenConnections  int64
	ClosedConnection int64
	BytesIn          int64
	BytesOut         int64
}

type GeoData struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`

	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`

	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
		TimeZone  string  `maxminddb:"time_zone"`
	} `maxminddb:"location"`
}

func (n *NetworkStats) Flush() NetworkStats {
	s := NetworkStats{
		OpenConnections:  atomic.LoadInt64(&n.OpenConnections),
		ClosedConnection: atomic.LoadInt64(&n.ClosedConnection),
		BytesIn:          atomic.LoadInt64(&n.BytesIn),
		BytesOut:         atomic.LoadInt64(&n.BytesOut),
	}
	atomic.StoreInt64(&n.OpenConnections, 0)
	atomic.StoreInt64(&n.ClosedConnection, 0)
	atomic.StoreInt64(&n.BytesIn, 0)
	atomic.StoreInt64(&n.BytesOut, 0)
	return s
}

func (a *Record) NormalisePath(globalConfig *config.Config) {
	if globalConfig.AnalyticsConfig.NormaliseUrls.NormaliseUUIDs {
		a.Path = globalConfig.AnalyticsConfig.NormaliseUrls.CompiledPatternSet.UUIDs.ReplaceAllString(a.Path, "{uuid}")
	}
	if globalConfig.AnalyticsConfig.NormaliseUrls.NormaliseNumbers {
		a.Path = globalConfig.AnalyticsConfig.NormaliseUrls.CompiledPatternSet.IDs.ReplaceAllString(a.Path, "/{id}")
	}
	for _, r := range globalConfig.AnalyticsConfig.NormaliseUrls.CompiledPatternSet.Custom {
		a.Path = r.ReplaceAllString(a.Path, "{var}")
	}
}

func (a *Record) SetExpiry(expiresInSeconds int64) {
	expiry := time.Duration(expiresInSeconds) * time.Second
	if expiresInSeconds == 0 {
		// Expiry is set to 100 years
		expiry = (24 * time.Hour) * (365 * 100)
	}

	t := time.Now()
	t2 := t.Add(expiry)
	a.ExpireAt = t2
}
