package main

import (
	"fmt"
	"github.com/nu7hatch/gouuid"
	"github.com/vmihailenco/msgpack"
	"time"
	"os"
	"encoding/csv"
	"strconv"
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
}

// AnalyticsError is an error for when writing to the storage engine fails
type AnalyticsError struct{}

func (e AnalyticsError) Error() string {
	return "Recording request failed!"
}

type AnalyticsHandler interface {
	RecordHit(AnalyticsRecord) error
}

type Purger interface {
	PurgeCache()
	StartPurgeLoop(int)
}

type RedisAnalyticsHandler struct {
	Store *RedisStorageManager
	Clean Purger
}

func (r RedisAnalyticsHandler) RecordHit(thisRecord AnalyticsRecord) error {
	encoded, err := msgpack.Marshal(thisRecord)
	u5, _ := uuid.NewV4()

	keyName := fmt.Sprintf("%d%d%d%d-%s", thisRecord.Year, thisRecord.Month, thisRecord.Day, thisRecord.Hour, u5.String())

	if err != nil {
		log.Error("Error encoding analytics data:")
		log.Error(err)
		return AnalyticsError{}
	} else {
		r.Store.SetKey(keyName, string(encoded))
	}

	return nil
}

type CSVPurger struct {
	Store	*RedisStorageManager
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

	var headers = []string { "METHOD", "PATH", "SIZE", "UA", "DAY", "MONTH", "YEAR", "HOUR", "RESPONSE" }

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
				toWrite := []string {
					decoded.Method,
					decoded.Path,
					strconv.FormatInt(decoded.ContentLength, 10),
					decoded.UserAgent,
					strconv.Itoa(decoded.Day),
					decoded.Month.String(),
					strconv.Itoa(decoded.Year),
					strconv.Itoa(decoded.Hour),
					strconv.Itoa(decoded.ResponseCode)}
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
