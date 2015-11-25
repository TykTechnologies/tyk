package main

import (
	"encoding/csv"
	"fmt"
	"gopkg.in/mgo.v2"
	"gopkg.in/vmihailenco/msgpack.v2"
	"os"
	"strconv"
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

// Purger is an interface that will define how the in-memory store will be purged
// of analytics data to prevent it growing too large
type Purger interface {
	PurgeCache()
	StartPurgeLoop(int)
}

// RedisAnalyticsHandler implements AnalyticsHandler and will record analytics
// data to a redis back end as defined in the Config object
type RedisAnalyticsHandler struct {
	Store *RedisClusterStorageManager
	Clean Purger
}

// RecordHit will store an AnalyticsRecord in Redis
func (r RedisAnalyticsHandler) RecordHit(thisRecord AnalyticsRecord) error {
	// If we are obfuscating API Keys, store the hashed representation (config check handled in hashing function)
	thisRecord.APIKey = publicHash(thisRecord.APIKey)

	if config.SlaveOptions.UseRPC {
		// Extend tag list to include this data so wecan segment by node if necessary
		thisRecord.Tags = append([]string{"tyk-hybrid-rpc"})
	}

	if config.DBAppConfOptions.NodeIsSegmented {
		// Extend tag list to include this data so wecan segment by node if necessary
		thisRecord.Tags = append(thisRecord.Tags, config.DBAppConfOptions.Tags...)
	}

	encoded, err := msgpack.Marshal(thisRecord)

	if err != nil {
		log.Error("Error encoding analytics data:")
		log.Error(err)
		return AnalyticsError{}
	}

	r.Store.AppendToSet(ANALYTICS_KEYNAME, string(encoded))

	return nil
}

// CSVPurger purges the in-memory analytics store to a CSV file as defined in the Config object
type CSVPurger struct {
	Store *RedisClusterStorageManager
}

// StartPurgeLoop is used as a goroutine to ensure that the cache is purged
// of analytics data (assuring size is small).
func (c CSVPurger) StartPurgeLoop(nextCount int) {
	time.Sleep(time.Duration(nextCount) * time.Second)
	c.PurgeCache()
	c.StartPurgeLoop(nextCount)
}

// PurgeCache Will pull all the analytics data from the
// cache and drop it to a storage engine, in this case a CSV file
func (c CSVPurger) PurgeCache() {
	curtime := time.Now()
	fname := fmt.Sprintf("%s%d-%s-%d-%d-%d.csv", config.AnalyticsConfig.CSVDir, curtime.Year(), curtime.Month().String(), curtime.Day(), curtime.Hour(), curtime.Minute())

	ferr := os.MkdirAll(config.AnalyticsConfig.CSVDir, 0777)
	if ferr != nil {
		log.Error(ferr)
	}
	outfile, _ := os.Create(fname)
	defer outfile.Close()
	writer := csv.NewWriter(outfile)

	var headers = []string{"METHOD", "PATH", "SIZE", "UA", "DAY", "MONTH", "YEAR", "HOUR", "RESPONSE", "APINAME", "APIVERSION"}

	err := writer.Write(headers)
	if err != nil {
		log.Error("Failed to write file headers!")
		log.Error(err)
	} else {
		KeyValueMap := c.Store.GetKeysAndValues()
		keys := []string{}

		for k, v := range KeyValueMap {
			keys = append(keys, k)
			decoded := AnalyticsRecord{}
			err := msgpack.Unmarshal([]byte(v), &decoded)
			if err != nil {
				log.Error("Couldn't unmarshal analytics data:")
				log.Error(err)
			} else {
				toWrite := []string{
					decoded.Method,
					decoded.Path,
					strconv.FormatInt(decoded.ContentLength, 10),
					decoded.UserAgent,
					strconv.Itoa(decoded.Day),
					decoded.Month.String(),
					strconv.Itoa(decoded.Year),
					strconv.Itoa(decoded.Hour),
					strconv.Itoa(decoded.ResponseCode),
					decoded.APIName,
					decoded.APIVersion}
				err := writer.Write(toWrite)
				if err != nil {
					log.Error("File write failed!")
					log.Error(err)
				}
			}
		}
		writer.Flush()
		c.Store.DeleteKeys(keys)
	}
}

// MongoPurger will purge analytics data into a Mongo database, requires that the Mongo DB string is specified
// in the Config object
type MongoPurger struct {
	Store          *RedisClusterStorageManager
	dbSession      *mgo.Session
	CollectionName string
	SetKeyName     string
}

// Connect Connects to Mongo
func (m *MongoPurger) Connect() {
	var err error
	m.dbSession, err = mgo.Dial(config.AnalyticsConfig.MongoURL)
	if err != nil {
		log.Error("Mongo connection failed:", err)
		time.Sleep(5)
		m.Connect()
	}
}

// StartPurgeLoop starts the loop that will be started as a goroutine and pull data out of the in-memory
// store and into MongoDB
func (m MongoPurger) StartPurgeLoop(nextCount int) {
	time.Sleep(time.Duration(nextCount) * time.Second)
	m.PurgeCache()
	m.StartPurgeLoop(nextCount)
}

// PurgeCache will pull the data from the in-memory store and drop it into the specified MongoDB collection
func (m *MongoPurger) PurgeCache() {
	if m.dbSession == nil {
		log.Debug("Connecting to analytics store")
		m.Connect()
		m.PurgeCache()
	} else {
		collectionName := config.AnalyticsConfig.MongoCollection
		if m.CollectionName != "" {
			collectionName = m.CollectionName
		}
		analyticsCollection := m.dbSession.DB("").C(collectionName)

		analyticsKeyName := ANALYTICS_KEYNAME
		if m.SetKeyName != "" {
			analyticsKeyName = m.SetKeyName
		}
		AnalyticsValues := m.Store.GetAndDeleteSet(analyticsKeyName)

		if len(AnalyticsValues) > 0 {
			keys := make([]interface{}, len(AnalyticsValues), len(AnalyticsValues))

			for i, v := range AnalyticsValues {
				decoded := AnalyticsRecord{}
				err := msgpack.Unmarshal(v.([]byte), &decoded)
				log.Debug("Decoded Record: ", decoded)
				if err != nil {
					log.Error("Couldn't unmarshal analytics data:")
					log.Error(err)
				} else {
					keys[i] = interface{}(decoded)
				}
			}

			err := analyticsCollection.Insert(keys...)
			if err != nil {
				log.Error("Problem inserting to mongo collection: ", err)
			}
		}
	}

}

// MongoPurger will purge analytics data into a Mongo database, requires that the Mongo DB string is specified
// in the Config object
type MongoUptimePurger struct {
	Store          *RedisClusterStorageManager
	dbSession      *mgo.Session
	CollectionName string
	SetKeyName     string
}

// Connect Connects to Mongo
func (m *MongoUptimePurger) Connect() {
	var err error
	m.dbSession, err = mgo.Dial(config.AnalyticsConfig.MongoURL)
	if err != nil {
		log.Error("Mongo connection failed:", err)
		time.Sleep(5)
		m.Connect()
	}
}

// StartPurgeLoop starts the loop that will be started as a goroutine and pull data out of the in-memory
// store and into MongoDB
func (m MongoUptimePurger) StartPurgeLoop(nextCount int) {
	time.Sleep(time.Duration(nextCount) * time.Second)
	m.PurgeCache()
	m.StartPurgeLoop(nextCount)
}

// PurgeCache will pull the data from the in-memory store and drop it into the specified MongoDB collection
func (m *MongoUptimePurger) PurgeCache() {
	if m.dbSession == nil {
		log.Debug("Connecting to analytics store")
		m.Connect()
		m.PurgeCache()
	} else {
		collectionName := config.AnalyticsConfig.MongoCollection
		if m.CollectionName != "" {
			collectionName = m.CollectionName
		}
		analyticsCollection := m.dbSession.DB("").C(collectionName)

		analyticsKeyName := ANALYTICS_KEYNAME
		if m.SetKeyName != "" {
			analyticsKeyName = m.SetKeyName
		}
		log.Debug("Getting from: ", analyticsKeyName)
		AnalyticsValues := m.Store.GetAndDeleteSet(analyticsKeyName)

		if len(AnalyticsValues) > 0 {
			keys := make([]interface{}, len(AnalyticsValues), len(AnalyticsValues))

			for i, v := range AnalyticsValues {
				decoded := UptimeReportData{}
				err := msgpack.Unmarshal(v.([]byte), &decoded)
				log.Debug("Decoded Record: ", decoded)
				if err != nil {
					log.Error("Couldn't unmarshal analytics data:")
					log.Error(err)
				} else {
					keys[i] = interface{}(decoded)
				}
			}

			err := analyticsCollection.Insert(keys...)
			if err != nil {
				log.Error("Problem inserting to mongo collection: ", err)
			}
		}
	}

}

type MockPurger struct {
	Store *RedisClusterStorageManager
}

// Connect does nothing
func (m *MockPurger) Connect() {}

// StartPurgeLoop does nothing
func (m MockPurger) StartPurgeLoop(nextCount int) {}

// PurgeCache will just empty redis
func (m *MockPurger) PurgeCache() {

	KeyValueMap := m.Store.GetKeysAndValues()

	if len(KeyValueMap) > 0 {
		keyNames := make([]string, len(KeyValueMap), len(KeyValueMap))

		i := 0
		for k, _ := range KeyValueMap {
			keyNames[i] = k
			i++
		}

		m.Store.DeleteKeys(keyNames)
	}

}
