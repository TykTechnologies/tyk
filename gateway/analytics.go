package gateway

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang"
	msgpack "gopkg.in/vmihailenco/msgpack.v2"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/regexp"
	"github.com/TykTechnologies/tyk/storage"
)

type NetworkStats struct {
	OpenConnections  int64
	ClosedConnection int64
	BytesIn          int64
	BytesOut         int64
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

// AnalyticsRecord encodes the details of a request
type AnalyticsRecord struct {
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

const analyticsKeyName = "tyk-system-analytics"

const (
	minRecordsBufferSize             = 1000
	recordsBufferFlushInterval       = 200 * time.Millisecond
	recordsBufferForcedFlushInterval = 1 * time.Second
)

func (a *AnalyticsRecord) GetGeo(ipStr string) {
	// Not great, tightly coupled
	if analytics.GeoIPDB == nil {
		return
	}

	record, err := geoIPLookup(ipStr)
	if err != nil {
		log.Error("GeoIP Failure (not recorded): ", err)
		return
	}
	if record == nil {
		return
	}

	log.Debug("ISO Code: ", record.Country.ISOCode)
	log.Debug("City: ", record.City.Names["en"])
	log.Debug("Lat: ", record.Location.Latitude)
	log.Debug("Lon: ", record.Location.Longitude)
	log.Debug("TZ: ", record.Location.TimeZone)

	a.Geo = *record
}

func geoIPLookup(ipStr string) (*GeoData, error) {
	if ipStr == "" {
		return nil, nil
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address %q", ipStr)
	}
	record := new(GeoData)
	if err := analytics.GeoIPDB.Lookup(ip, record); err != nil {
		return nil, fmt.Errorf("geoIPDB lookup of %q failed: %v", ipStr, err)
	}
	return record, nil
}

func initNormalisationPatterns() (pats config.NormaliseURLPatterns) {
	pats.UUIDs = regexp.MustCompile(`[0-9a-fA-F]{8}(-)?[0-9a-fA-F]{4}(-)?[0-9a-fA-F]{4}(-)?[0-9a-fA-F]{4}(-)?[0-9a-fA-F]{12}`)
	pats.IDs = regexp.MustCompile(`\/(\d+)`)

	for _, pattern := range config.Global().AnalyticsConfig.NormaliseUrls.Custom {
		if patRe, err := regexp.Compile(pattern); err != nil {
			log.Error("failed to compile custom pattern: ", err)
		} else {
			pats.Custom = append(pats.Custom, patRe)
		}
	}
	return
}

func (a *AnalyticsRecord) NormalisePath(globalConfig *config.Config) {
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

func (a *AnalyticsRecord) SetExpiry(expiresInSeconds int64) {
	expiry := time.Duration(expiresInSeconds) * time.Second
	if expiresInSeconds == 0 {
		// Expiry is set to 100 years
		expiry = (24 * time.Hour) * (365 * 100)
	}

	t := time.Now()
	t2 := t.Add(expiry)
	a.ExpireAt = t2
}

// RedisAnalyticsHandler will record analytics data to a redis back end
// as defined in the Config object
type RedisAnalyticsHandler struct {
	Store            storage.Handler
	Clean            Purger
	GeoIPDB          *maxminddb.Reader
	globalConf       config.Config
	recordsChan      chan *AnalyticsRecord
	workerBufferSize uint64
	shouldStop       uint32
	poolWg           sync.WaitGroup
}

func (r *RedisAnalyticsHandler) Init(globalConf config.Config) {
	r.globalConf = globalConf

	if r.globalConf.AnalyticsConfig.EnableGeoIP {
		if db, err := maxminddb.Open(r.globalConf.AnalyticsConfig.GeoIPDBLocation); err != nil {
			log.Error("Failed to init GeoIP Database: ", err)
		} else {
			r.GeoIPDB = db
		}
	}

	analytics.Store.Connect()

	ps := r.globalConf.AnalyticsConfig.PoolSize
	if ps == 0 {
		ps = 50
	}
	log.WithField("ps", ps).Debug("Analytics pool workers number")

	recordsBufferSize := r.globalConf.AnalyticsConfig.RecordsBufferSize
	if recordsBufferSize < minRecordsBufferSize {
		recordsBufferSize = minRecordsBufferSize // force it to this value
	}
	log.WithField("recordsBufferSize", recordsBufferSize).Debug("Analytics total buffer (channel) size")

	r.workerBufferSize = recordsBufferSize / uint64(ps)
	log.WithField("workerBufferSize", r.workerBufferSize).Debug("Analytics pool worker buffer size")

	r.recordsChan = make(chan *AnalyticsRecord, recordsBufferSize)

	// start worker pool
	atomic.SwapUint32(&r.shouldStop, 0)
	for i := 0; i < ps; i++ {
		r.poolWg.Add(1)
		go r.recordWorker()
	}
}

func (r *RedisAnalyticsHandler) Stop() {
	// flag to stop sending records into channel
	atomic.SwapUint32(&r.shouldStop, 1)

	// close channel to stop workers
	close(r.recordsChan)

	// wait for all workers to be done
	r.poolWg.Wait()
}

// RecordHit will store an AnalyticsRecord in Redis
func (r *RedisAnalyticsHandler) RecordHit(record *AnalyticsRecord) error {
	// check if we should stop sending records 1st
	if atomic.LoadUint32(&r.shouldStop) > 0 {
		return nil
	}

	// just send record to channel consumed by pool of workers
	// leave all data crunching and Redis I/O work for pool workers
	r.recordsChan <- record

	return nil
}

func (r *RedisAnalyticsHandler) recordWorker() {
	defer r.poolWg.Done()

	// this is buffer to send one pipelined command to redis
	// use r.recordsBufferSize as cap to reduce slice re-allocations
	recordsBuffer := make([]string, 0, r.workerBufferSize)

	// read records from channel and process
	lastSentTs := time.Now()
	for {
		readyToSend := false
		select {

		case record, ok := <-r.recordsChan:
			// check if channel was closed and it is time to exit from worker
			if !ok {
				// send what is left in buffer
				r.Store.AppendToSetPipelined(analyticsKeyName, recordsBuffer)
				return
			}

			// we have new record - prepare it and add to buffer

			// If we are obfuscating API Keys, store the hashed representation (config check handled in hashing function)
			record.APIKey = storage.HashKey(record.APIKey)

			if r.globalConf.SlaveOptions.UseRPC {
				// Extend tag list to include this data so wecan segment by node if necessary
				record.Tags = append(record.Tags, "tyk-hybrid-rpc")
			}

			if r.globalConf.DBAppConfOptions.NodeIsSegmented {
				// Extend tag list to include this data so we can segment by node if necessary
				record.Tags = append(record.Tags, r.globalConf.DBAppConfOptions.Tags...)
			}

			// Lets add some metadata
			if record.APIKey != "" {
				record.Tags = append(record.Tags, "key-"+record.APIKey)
			}

			if record.OrgID != "" {
				record.Tags = append(record.Tags, "org-"+record.OrgID)
			}

			record.Tags = append(record.Tags, "api-"+record.APIID)

			// fix paths in record as they might have omitted leading "/"
			if !strings.HasPrefix(record.Path, "/") {
				record.Path = "/" + record.Path
			}
			if !strings.HasPrefix(record.RawPath, "/") {
				record.RawPath = "/" + record.RawPath
			}

			if encoded, err := msgpack.Marshal(record); err != nil {
				log.WithError(err).Error("Error encoding analytics data")
			} else {
				recordsBuffer = append(recordsBuffer, string(encoded))
			}

			// identify that buffer is ready to be sent
			readyToSend = uint64(len(recordsBuffer)) == r.workerBufferSize

		case <-time.After(recordsBufferFlushInterval):
			// nothing was received for that period of time
			// anyways send whatever we have, don't hold data too long in buffer
			readyToSend = true
		}

		// send data to Redis and reset buffer
		if len(recordsBuffer) > 0 && (readyToSend || time.Since(lastSentTs) >= recordsBufferForcedFlushInterval) {
			r.Store.AppendToSetPipelined(analyticsKeyName, recordsBuffer)
			recordsBuffer = make([]string, 0, r.workerBufferSize)
			lastSentTs = time.Now()
		}
	}
}
