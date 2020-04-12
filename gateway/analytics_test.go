package gateway

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"

	"github.com/TykTechnologies/tyk/config"
	tyk_analytics "github.com/TykTechnologies/tyk/gateway/analytics_pb"
	"github.com/golang/protobuf/proto"
	"gopkg.in/vmihailenco/msgpack.v2"
)

func TestGeoIPLookup(t *testing.T) {
	testCases := [...]struct {
		in      string
		wantErr bool
	}{
		{"", false},
		{"foobar", true},
		{"1.2.3.4", false},
	}
	for _, tc := range testCases {
		_, err := geoIPLookup(tc.in)
		switch {
		case tc.wantErr && err == nil:
			t.Errorf("geoIPLookup(%q) did not error", tc.in)
		case !tc.wantErr && err != nil:
			t.Errorf("geoIPLookup(%q) errored", tc.in)
		}
	}
}

func TestURLReplacer(t *testing.T) {
	defer ResetTestConfig()
	globalConf := config.Global()
	globalConf.AnalyticsConfig.NormaliseUrls.Enabled = true
	globalConf.AnalyticsConfig.NormaliseUrls.NormaliseUUIDs = true
	globalConf.AnalyticsConfig.NormaliseUrls.NormaliseNumbers = true
	globalConf.AnalyticsConfig.NormaliseUrls.Custom = []string{"ihatethisstring"}
	config.SetGlobal(globalConf)

	recordUUID1 := AnalyticsRecord{Path: "/15873a748894492162c402d67e92283b/search"}
	recordUUID2 := AnalyticsRecord{Path: "/CA761232-ED42-11CE-BACD-00AA0057B223/search"}
	recordUUID3 := AnalyticsRecord{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
	recordUUID4 := AnalyticsRecord{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
	recordID1 := AnalyticsRecord{Path: "/widgets/123456/getParams"}
	recordCust := AnalyticsRecord{Path: "/widgets/123456/getParams/ihatethisstring"}

	globalConf.AnalyticsConfig.NormaliseUrls.CompiledPatternSet = initNormalisationPatterns()
	config.SetGlobal(globalConf)

	recordUUID1.NormalisePath(&globalConf)
	recordUUID2.NormalisePath(&globalConf)
	recordUUID3.NormalisePath(&globalConf)
	recordUUID4.NormalisePath(&globalConf)
	recordID1.NormalisePath(&globalConf)
	recordCust.NormalisePath(&globalConf)

	if recordUUID1.Path != "/{uuid}/search" {
		t.Error("Path not altered, is:")
		t.Error(recordUUID1.Path)
		t.Error(config.Global().AnalyticsConfig.NormaliseUrls)
	}

	if recordUUID2.Path != "/{uuid}/search" {
		t.Error("Path not altered, is:")
		t.Error(recordUUID2.Path)
	}

	if recordUUID3.Path != "/{uuid}/search" {
		t.Error("Path not altered, is:")
		t.Error(recordUUID3.Path)
	}

	if recordUUID4.Path != "/{uuid}/search" {
		t.Error("Path not altered, is:")
		t.Error(recordUUID4.Path)
	}

	if recordID1.Path != "/widgets/{id}/getParams" {
		t.Error("Path not altered, is:")
		t.Error(recordID1.Path)
	}

	if recordCust.Path != "/widgets/{id}/getParams/{var}" {
		t.Error("Path not altered, is:")
		t.Error(recordCust.Path)
	}
}

func BenchmarkURLReplacer(b *testing.B) {
	b.ReportAllocs()

	defer ResetTestConfig()

	globalConf := config.Global()
	globalConf.AnalyticsConfig.NormaliseUrls.Enabled = true
	globalConf.AnalyticsConfig.NormaliseUrls.NormaliseUUIDs = true
	globalConf.AnalyticsConfig.NormaliseUrls.NormaliseNumbers = true
	globalConf.AnalyticsConfig.NormaliseUrls.Custom = []string{"ihatethisstring"}
	globalConf.AnalyticsConfig.NormaliseUrls.CompiledPatternSet = initNormalisationPatterns()
	config.SetGlobal(globalConf)

	for i := 0; i < b.N; i++ {
		recordUUID1 := AnalyticsRecord{Path: "/15873a748894492162c402d67e92283b/search"}
		recordUUID2 := AnalyticsRecord{Path: "/CA761232-ED42-11CE-BACD-00AA0057B223/search"}
		recordUUID3 := AnalyticsRecord{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
		recordUUID4 := AnalyticsRecord{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
		recordID1 := AnalyticsRecord{Path: "/widgets/123456/getParams"}
		recordCust := AnalyticsRecord{Path: "/widgets/123456/getParams/ihatethisstring"}

		recordUUID1.NormalisePath(&globalConf)
		recordUUID2.NormalisePath(&globalConf)
		recordUUID3.NormalisePath(&globalConf)
		recordUUID4.NormalisePath(&globalConf)
		recordID1.NormalisePath(&globalConf)
		recordCust.NormalisePath(&globalConf)
	}
}

func TestTagHeaders(t *testing.T) {
	req := TestReq(t, "GET", "/tagmeplease", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tag-Me", "1")
	req.Header.Set("X-Tag-Me2", "2")
	req.Header.Set("X-Tag-Me3", "3")
	req.Header.Set("X-Ignore-Me", "4")

	existingTags := []string{"first", "second"}
	existingTags = tagHeaders(req, []string{
		"x-tag-me",
		"x-tag-me2",
		"x-tag-me3"},
		existingTags)

	if len(existingTags) == 2 {
		t.Fatal("Existing tags have not been expanded")
	}

	if len(existingTags) != 5 {
		t.Fatalf("Wrong number of tags, got %v, wanted %v", len(existingTags), 5)
	}

	check := map[string]bool{
		"x-tag-me-1":  true,
		"x-tag-me2-2": true,
		"x-tag-me3-3": true,
	}

	for _, t := range existingTags {
		_, ok := check[t]
		if ok {
			delete(check, t)
		}
	}

	if len(check) != 0 {
		t.Fatalf("Header values not proerly set, got: %v, remnainder: %v", existingTags, check)
	}

}

func BenchmarkTagHeaders(b *testing.B) {
	b.ReportAllocs()

	req := TestReq(b, "GET", "/tagmeplease", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tag-Me", "1")
	req.Header.Set("X-Tag-Me2", "2")
	req.Header.Set("X-Tag-Me3", "3")
	req.Header.Set("X-Ignore-Me", "4")

	existingTags := []string{"first", "second"}

	var newExistingTags []string
	for i := 0; i < b.N; i++ {
		newExistingTags = tagHeaders(
			req,
			[]string{
				"x-tag-me",
				"x-tag-me2",
				"x-tag-me3",
			},
			existingTags,
		)
		if len(newExistingTags) == 2 {
			b.Fatal("Existing tags have not been expanded")
		}
	}
}

var fakeRecord = AnalyticsRecord{
	Method:        http.MethodGet,
	Host:          "httpbin.org",
	Path:          "/get",
	RawPath:       "/get",
	ContentLength: 0,
	UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1664.3 Safari/537.36",
	Day:           7,
	Month:         6,
	Year:          1982,
	Hour:          1,
	ResponseCode:  200,
	APIKey:        "myhash",
	TimeStamp:     time.Now(),
	APIVersion:    "v1",
	APIName:       "httpbin",
	APIID:         "httpbin",
	OrgID:         "none",
	OauthID:       "",
	RequestTime:   3,
	Latency: Latency{
		Total:    10,
		Upstream: 8,
	},
	RawRequest:  "",
	RawResponse: "",
	IPAddress:   "127.0.0.1",
	Geo:         GeoData{},
	Network:     NetworkStats{},
	Tags:        nil,
	Alias:       "",
	TrackPath:   false,
	ExpireAt:    time.Time{},
}

var fakeRecordProto = tyk_analytics.AnalyticsRecord{
	Method:        http.MethodGet,
	Host:          "httpbin.org",
	Path:          "/get",
	RawPath:       "/get",
	ContentLength: 0,
	UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1664.3 Safari/537.36",
	Day:           7,
	Month:         6,
	Year:          1982,
	Hour:          1,
	ResponseCode:  200,
	APIKey:        "myhash",
	TimeStamp:     &timestamp.Timestamp{Seconds: int64(time.Now().Second())},
	APIVersion:    "v1",
	APIName:       "httpbin",
	APIID:         "httpbin",
	OrgID:         "none",
	RequestTime:   3,
	Latency: &tyk_analytics.AnalyticsRecord_Latency{
		Total:    10,
		Upstream: 8,
	},
	RawRequest:  "",
	RawResponse: "",
	IPAddress:   "127.0.0.1",
	Geo:         &tyk_analytics.AnalyticsRecord_GeoData{},
	Network:     &tyk_analytics.AnalyticsRecord_NetworkStats{},
	Tags:        nil,
	Alias:       "",
	TrackPath:   false,
	ExpireAt:    &timestamp.Timestamp{},
}

func BenchmarkMsgpackMarshal(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = msgpack.Marshal(fakeRecord)
	}
}

func BenchmarkGogoProtobuf(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = proto.Marshal(&fakeRecordProto)
	}
}
