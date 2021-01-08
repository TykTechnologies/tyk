package analyticspb

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"reflect"

	"github.com/TykTechnologies/tyk/config"
	"github.com/oschwald/maxminddb-golang"
	"github.com/prometheus/common/log"
	"google.golang.org/protobuf/types/known/timestamppb"
	"github.com/golang/protobuf/ptypes"

)

func (a *AnalyticsRecord) GetFieldNames() []string {
	val := reflect.ValueOf(a).Elem()
	fields := []string{}

	for i := 0; i < val.NumField(); i++ {
		typeField := val.Type().Field(i)
		fields = append(fields, typeField.Name)
	}

	return fields
}

func (a *AnalyticsRecord) GetLineValues() []string {
	val := reflect.ValueOf(a).Elem()
	fields := []string{}

	for i := 0; i < val.NumField(); i++ {
		valueField := val.Field(i)
		typeField := val.Type().Field(i)
		thisVal := ""
		switch typeField.Type.String() {
		case "int":
			thisVal = strconv.Itoa(int(valueField.Int()))
		case "int64":
			thisVal = strconv.Itoa(int(valueField.Int()))
		case "[]string":
			tmpVal := valueField.Interface().([]string)
			thisVal = strings.Join(tmpVal, ";")
		case "time.Time":
			tmpVal := valueField.Interface().(time.Time)
			thisVal = tmpVal.String()
		case "time.Month":
			tmpVal := valueField.Interface().(time.Month)
			thisVal = tmpVal.String()
		default:
			thisVal = valueField.String()
		}

		fields = append(fields, thisVal)
	}

	return fields
}

func (a *AnalyticsRecord) GetGeoDataData(GeoIPDB *maxminddb.Reader, ipStr string) {
	// Not great, tightly coupled
	if GeoIPDB == nil {
		return
	}

	record, err := geoIPLookup(GeoIPDB, ipStr)
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

	a.Geo = record
}

func geoIPLookup(GeoIPDB *maxminddb.Reader, ipStr string) (*GeoData, error) {
	if ipStr == "" {
		return nil, nil
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address %q", ipStr)
	}
	record := new(GeoData)
	if err := GeoIPDB.Lookup(ip, record); err != nil {
		return nil, fmt.Errorf("geoIPDB lookup of %q failed: %v", ipStr, err)
	}
	return record, nil
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

func (a *AnalyticsRecord) SetExpiry(expiresAfter int64) {
	calcExpiry := func(expiresAfter int64) time.Time {
		expiry := time.Duration(expiresAfter) * time.Second
		if expiresAfter == 0 {
			// Expiry is set to 100 years
			expiry = (24 * time.Hour) * (365 * 100)
		}

		t := time.Now()
		t2 := t.Add(expiry)
		return t2
	}
	a.ExpireAt = &timestamppb.Timestamp{Seconds: calcExpiry(expiresAfter).Unix()}
}

func (a *AnalyticsRecord) GetTimestampAsTime() time.Time{
	var timer time.Time
	if a.TimeStamp!= nil {
		timer, _ = ptypes.Timestamp(a.TimeStamp)
	}
	return timer
}

func (a *AnalyticsRecord) GetExpireAtsTime() time.Time{
	var timer time.Time
	if a.ExpireAt!= nil {
		timer, _ = ptypes.Timestamp(a.ExpireAt)
	}
	return timer
}

func (a *AnalyticsRecord) SetTimestampAsTime(timer time.Time) {
	timestamp, _ := ptypes.TimestampProto(timer)
	a.TimeStamp = timestamp
}

func (a *AnalyticsRecord) SetExpireAtsTime(timer time.Time) {
	timestamp, _ := ptypes.TimestampProto(timer)
	a.ExpireAt = timestamp
}

func (n *NetworkStats) Flush() NetworkStats {
	s := NetworkStats{
		OpenConnections:  atomic.LoadInt64(&n.OpenConnections),
		ClosedConnections: atomic.LoadInt64(&n.ClosedConnections),
		BytesIn:          atomic.LoadInt64(&n.BytesIn),
		BytesOut:         atomic.LoadInt64(&n.BytesOut),
	}
	atomic.StoreInt64(&n.OpenConnections, 0)
	atomic.StoreInt64(&n.ClosedConnections, 0)
	atomic.StoreInt64(&n.BytesIn, 0)
	atomic.StoreInt64(&n.BytesOut, 0)
	return s
}