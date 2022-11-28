package main

import (
	"net"
	"regexp"
	"time"

	"github.com/Jeffail/tunny"
	"github.com/oschwald/maxminddb-golang"
	"gopkg.in/vmihailenco/msgpack.v2"
)

// AnalyticsRecord encodes the details of a request
type AnalyticsRecord struct {
	Method        string
	Path          string
	RawPath       string
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
	IPAddress     string
	Geo           GeoData
	Tags          []string
	Alias         string
	TrackPath     bool
	ExpireAt      time.Time `bson:"expireAt" json:"expireAt"`
}

type GeoData struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`

	City struct {
		GeoNameID uint              `maxminddb:"geoname_id"`
		Names     map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`

	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
		TimeZone  string  `maxminddb:"time_zone"`
	} `maxminddb:"location"`
}

const (
	ANALYTICS_KEYNAME string = "tyk-system-analytics"
)

func (a *AnalyticsRecord) GetGeo(ipStr string) {
	if !config.AnalyticsConfig.EnableGeoIP {
		return
	}

	// Not great, tightly coupled
	if analytics.GeoIPDB == nil {
		return
	}

	// Sometimes it is empty, we can't look up mpty IP addresses
	if ipStr == "" {
		return
	}

	ip := net.ParseIP(ipStr)

	var record GeoData // Or any appropriate struct
	err := analytics.GeoIPDB.Lookup(ip, &record)
	if err != nil {
		log.Error("GeoIP Failure (not recorded): ", err)
		return
	}

	log.Debug("ISO Code: ", record.Country.ISOCode)
	log.Debug("City: ", record.City.Names["en"])
	log.Debug("Lat: ", record.Location.Latitude)
	log.Debug("Lon: ", record.Location.Longitude)
	log.Debug("TZ: ", record.Location.TimeZone)

	a.Geo = record
}

type NormaliseURLPatterns struct {
	UUIDs  *regexp.Regexp
	IDs    *regexp.Regexp
	Custom []*regexp.Regexp
}

func InitNormalisationPatterns() NormaliseURLPatterns {
	thesePatterns := NormaliseURLPatterns{}

	uuidPat, pat1Err := regexp.Compile("[0-9a-fA-F]{8}(-)?[0-9a-fA-F]{4}(-)?[0-9a-fA-F]{4}(-)?[0-9a-fA-F]{4}(-)?[0-9a-fA-F]{12}")
	if pat1Err != nil {
		log.Error("failed to compile custom pattern: ", pat1Err)
	}

	numPat, pat2Err := regexp.Compile(`\/(\d+)`)
	if pat2Err != nil {
		log.Error("failed to compile custom pattern: ", pat2Err)
	}

	custPats := []*regexp.Regexp{}
	for _, pattern := range config.AnalyticsConfig.NormaliseUrls.Custom {
		thisPat, patErr := regexp.Compile(pattern)
		if patErr != nil {
			log.Error("failed to compile custom pattern: ", patErr)
		} else {
			custPats = append(custPats, thisPat)
		}
	}

	thesePatterns.UUIDs = uuidPat
	thesePatterns.IDs = numPat
	thesePatterns.Custom = custPats

	return thesePatterns
}

func (a *AnalyticsRecord) NormalisePath() {
	if config.AnalyticsConfig.NormaliseUrls.Enabled {
		if config.AnalyticsConfig.NormaliseUrls.NormaliseUUIDs {
			a.Path = config.AnalyticsConfig.NormaliseUrls.compiledPatternSet.UUIDs.ReplaceAllString(a.Path, "{uuid}")
		}
		if config.AnalyticsConfig.NormaliseUrls.NormaliseNumbers {
			a.Path = config.AnalyticsConfig.NormaliseUrls.compiledPatternSet.IDs.ReplaceAllString(a.Path, "/{id}")
		}
		if len(config.AnalyticsConfig.NormaliseUrls.compiledPatternSet.Custom) > 0 {
			for _, r := range config.AnalyticsConfig.NormaliseUrls.compiledPatternSet.Custom {
				a.Path = r.ReplaceAllString(a.Path, "{var}")
			}
		}
	}

}

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
	Init() error
	RecordHit(AnalyticsRecord) error
}

var AnalyticsPool *tunny.WorkPool

// RedisAnalyticsHandler implements AnalyticsHandler and will record analytics
// data to a redis back end as defined in the Config object
type RedisAnalyticsHandler struct {
	Store   *RedisClusterStorageManager
	Clean   Purger
	GeoIPDB *maxminddb.Reader
}

func (r *RedisAnalyticsHandler) Init() {
	if config.AnalyticsConfig.EnableGeoIP {
		go r.reloadDB()
	}

	analytics.Store.Connect()
	var err error

	ps := config.AnalyticsConfig.PoolSize
	if ps == 0 {
		ps = 50
	}

	AnalyticsPool, err = tunny.CreatePoolGeneric(ps).Open()
	if err != nil {
		log.Error("Failed to init analytics pool")
	}
}

func (r *RedisAnalyticsHandler) reloadDB() {
	thisDb, err := maxminddb.Open(config.AnalyticsConfig.GeoIPDBLocation)
	if err != nil {
		log.Error("Failed to init GeoIP Database: ", err)
	} else {
		oldDB := r.GeoIPDB
		r.GeoIPDB = thisDb
		if oldDB != nil {
			oldDB.Close()
		}

	}
	time.Sleep(time.Hour * 1)
}

// RecordHit will store an AnalyticsRecord in Redis
func (r RedisAnalyticsHandler) RecordHit(thisRecord AnalyticsRecord) error {

	AnalyticsPool.SendWork(func() {
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
			log.Error("Error encoding analytics data: ", err)
		}

		r.Store.AppendToSet(ANALYTICS_KEYNAME, string(encoded))
	})

	return nil

}
