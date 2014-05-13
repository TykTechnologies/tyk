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
	PurgeCache()
}

type RedisAnalyticsHandler struct {
	Store RedisStorageManager
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

func (r RedisAnalyticsHandler) PurgeCache() {
	// TODO: Create filename from time parameters
	// TODO: Configurable analytics directory
	// TODO: Configurable cache purge writer (e.g. PG)

	outfile, _ := os.Create("test.analytics.csv")
	defer outfile.Close()
	writer := csv.NewWriter(outfile)

	var headers = []string { "METHOD", "PATH", "SIZE", "UA", "DAY", "MONTH", "YEAR", "HOUR", "RESPONSE" }

	err := writer.Write(headers)
	if err != nil {
		log.Error("Failed to write file headers!")
		log.Error(err)
	} else {
		KeyValueMap := r.Store.GetKeysAndValues()
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
		r.Store.DeleteKeys(keys)
	}
}
