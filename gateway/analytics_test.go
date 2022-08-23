package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestAnalytics_Write(t *testing.T) {

	tcs := []struct {
		TestName            string
		analyticsSerializer string
	}{
		{
			TestName:            "Testing analytics flows with msgpack",
			analyticsSerializer: "",
		},
		{
			TestName:            "Testing analytics flows with protobuf",
			analyticsSerializer: "protobuf",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.TestName, func(t *testing.T) {
			ts := StartTest(func(globalConf *config.Config) {
				globalConf.AnalyticsConfig.SerializerType = tc.analyticsSerializer
			}, TestConfig{
				Delay: 20 * time.Millisecond,
			})

			defer ts.Close()
			base := ts.Gw.GetConfig()

			redisAnalyticsKeyName := analyticsKeyName + ts.Gw.Analytics.analyticsSerializer.GetSuffix()

			// Cleanup before test
			// let records to be sent
			ts.Gw.Analytics.Store.GetAndDeleteSet(redisAnalyticsKeyName)

			t.Run("Log errors", func(t *testing.T) {
				if err := ts.RemoveApis(); err != nil {
					t.Error("removing apis:" + err.Error())
				}
				ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
					spec.UseKeylessAccess = false
					spec.Proxy.ListenPath = "/"
				})

				_, err := ts.Run(t, []test.TestCase{
					{Path: "/", Code: 401},
					{Path: "/", Code: 401},
				}...)
				if err != nil {
					t.Error("Error executing test case")
				}

				//Restart will empty the analytics buffer into redis, stop the analytics processing and start it again
				ts.Gw.Analytics.Flush()

				results := ts.Gw.Analytics.Store.GetAndDeleteSet(redisAnalyticsKeyName)
				if len(results) != 2 {
					t.Error("Should return 2 record", len(results))
				}

				var record analytics.AnalyticsRecord
				err = ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
				if err != nil {
					t.Error("Error decoding analytics")
				}
				if record.ResponseCode != 401 {
					t.Error("Analytics record do not match: ", record)
				}
			})

			t.Run("Log success", func(t *testing.T) {
				if err := ts.RemoveApis(); err != nil {
					t.Error("removing apis:" + err.Error())
				}
				ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
					spec.UseKeylessAccess = false
					spec.Proxy.ListenPath = "/"
				})

				key := CreateSession(ts.Gw)

				authHeaders := map[string]string{
					"authorization": key,
				}

				_, err := ts.Run(t, test.TestCase{
					Path: "/", Headers: authHeaders, Code: 200,
				})
				if err != nil {
					t.Error("Error executing test case")
				}
				// let records to to be sent

				ts.Gw.Analytics.Flush()

				results := ts.Gw.Analytics.Store.GetAndDeleteSet(redisAnalyticsKeyName)
				if len(results) != 1 {
					t.Error("Should return 1 record: ", len(results))
				}

				var record analytics.AnalyticsRecord
				err = ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
				if err != nil {
					t.Error("Error decoding analytics")
				}
				if record.ResponseCode != 200 {
					t.Error("Analytics record do not match", record)
				}
			})

			t.Run("Detailed analytics with api spec config enabled", func(t *testing.T) {
				defer func() {
					ts.Gw.SetConfig(base)
				}()
				if err := ts.RemoveApis(); err != nil {
					t.Error("removing apis:" + err.Error())
				}

				globalConf := ts.Gw.GetConfig()
				globalConf.AnalyticsConfig.EnableDetailedRecording = false
				ts.Gw.SetConfig(globalConf)

				ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
					spec.UseKeylessAccess = false
					spec.Proxy.ListenPath = "/"
					spec.EnableDetailedRecording = true
				})

				key := CreateSession(ts.Gw)

				authHeaders := map[string]string{
					"authorization": key,
				}

				_, err := ts.Run(t, test.TestCase{
					Path: "/", Headers: authHeaders, Code: 200,
				})
				if err != nil {
					t.Error("Error executing test case")
				}

				// let records to  be sent
				ts.Gw.Analytics.Flush()

				results := ts.Gw.Analytics.Store.GetAndDeleteSet(redisAnalyticsKeyName)
				if len(results) != 1 {
					t.Error("Should return 1 record: ", len(results))
				}

				var record analytics.AnalyticsRecord
				err = ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
				if err != nil {
					t.Error("Error decoding analytics")
				}
				if record.ResponseCode != 200 {
					t.Error("Analytics record do not match", record)
				}

				if record.RawRequest == "" {
					t.Error("Detailed request info not found", record)
				}

				if record.RawResponse == "" {
					t.Error("Detailed response info not found", record)
				}
			})

			t.Run("Detailed analytics with only key flag set", func(t *testing.T) {
				defer func() {
					ts.Gw.SetConfig(base)
				}()
				globalConf := ts.Gw.GetConfig()
				globalConf.AnalyticsConfig.EnableDetailedRecording = false
				ts.Gw.SetConfig(globalConf)

				if err := ts.RemoveApis(); err != nil {
					t.Error("removing apis:" + err.Error())
				}

				ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
					spec.UseKeylessAccess = false
					spec.Proxy.ListenPath = "/"
					spec.EnableDetailedRecording = false
				})

				key := CreateSession(ts.Gw, func(sess *user.SessionState) {
					sess.EnableDetailedRecording = true
				})

				authHeaders := map[string]string{
					"authorization": key,
				}

				_, err := ts.Run(t, test.TestCase{
					Path: "/", Headers: authHeaders, Code: 200,
				})
				if err != nil {
					t.Error("Error executing test case")
				}

				// let records to to be sent
				ts.Gw.Analytics.Flush()

				results := ts.Gw.Analytics.Store.GetAndDeleteSet(redisAnalyticsKeyName)
				if len(results) != 1 {
					t.Error("Should return 1 record: ", len(results))
				}

				var record analytics.AnalyticsRecord
				err = ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
				if err != nil {
					t.Error("Error decoding analytics")
				}
				if record.ResponseCode != 200 {
					t.Error("Analytics record do not match", record)
				}

				if record.RawRequest == "" {
					t.Error("Detailed request info not found", record)
				}

				if record.RawResponse == "" {
					t.Error("Detailed response info not found", record)
				}
			})

			t.Run("Detailed analytics", func(t *testing.T) {
				defer func() {
					ts.Gw.SetConfig(base)
				}()
				globalConf := ts.Gw.GetConfig()
				globalConf.AnalyticsConfig.EnableDetailedRecording = true
				ts.Gw.SetConfig(globalConf)

				if err := ts.RemoveApis(); err != nil {
					t.Error("removing apis:" + err.Error())
				}
				ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
					spec.UseKeylessAccess = false
					spec.Proxy.ListenPath = "/"
				})

				key := CreateSession(ts.Gw)

				authHeaders := map[string]string{
					"authorization": key,
				}

				_, err := ts.Run(t, test.TestCase{
					Path: "/", Headers: authHeaders, Code: 200,
				})
				if err != nil {
					t.Error("Error executing test case")
				}
				// let records to to be sent
				ts.Gw.Analytics.Flush()

				results := ts.Gw.Analytics.Store.GetAndDeleteSet(redisAnalyticsKeyName)
				if len(results) != 1 {
					t.Error("Should return 1 record: ", len(results))
				}

				var record analytics.AnalyticsRecord
				err = ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
				if err != nil {
					t.Error("Error decoding analytics")
				}
				if record.ResponseCode != 200 {
					t.Error("Analytics record do not match", record)
				}

				if record.RawRequest == "" {
					t.Error("Detailed request info not found", record)
				}

				if record.RawResponse == "" {
					t.Error("Detailed response info not found", record)
				}
			})

			t.Run("Detailed analytics with latency", func(t *testing.T) {
				defer func() {
					ts.Gw.SetConfig(base)
				}()
				globalConf := ts.Gw.GetConfig()
				globalConf.AnalyticsConfig.EnableDetailedRecording = true
				ts.Gw.SetConfig(globalConf)
				ls := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// We are delaying the response by 2 ms. This is important because anytime
					// less than 0 eg  0.2 ms will be round off to 0 which is not good to check if we have
					// latency correctly set.
					time.Sleep(2 * time.Millisecond)
				}))
				defer ls.Close()

				if err := ts.RemoveApis(); err != nil {
					t.Error("removing apis:" + err.Error())
				}

				ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
					spec.UseKeylessAccess = false
					spec.Proxy.ListenPath = "/"
					spec.Proxy.TargetURL = ls.URL
				})

				key := CreateSession(ts.Gw)

				authHeaders := map[string]string{
					"authorization": key,
				}

				_, err := ts.Run(t, test.TestCase{
					Path: "/", Headers: authHeaders, Code: 200,
				})
				if err != nil {
					t.Error("Error executing test case")
				}

				// let records to to be sent
				ts.Gw.Analytics.Flush()

				results := ts.Gw.Analytics.Store.GetAndDeleteSet(redisAnalyticsKeyName)
				if len(results) != 1 {
					t.Error("Should return 1 record: ", len(results))
				}

				var record analytics.AnalyticsRecord
				err = ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
				if err != nil {
					t.Error("Error decoding analytics")
				}
				if record.ResponseCode != 200 {
					t.Error("Analytics record do not match", record)
				}

				if record.RawRequest == "" {
					t.Error("Detailed request info not found", record)
				}

				if record.RawResponse == "" {
					t.Error("Detailed response info not found", record)
				}
				if record.Latency.Total == 0 {
					t.Error("expected total latency to be set")
				}
				if record.Latency.Upstream == 0 {
					t.Error("expected upstream latency to be set")
				}
				if record.Latency.Total != record.RequestTime {
					t.Errorf("expected %d got %d", record.RequestTime, record.Latency.Total)
				}
			})

			t.Run("Detailed analytics with cache", func(t *testing.T) {
				defer func() {
					ts.Gw.SetConfig(base)
				}()
				globalConf := ts.Gw.GetConfig()
				globalConf.AnalyticsConfig.EnableDetailedRecording = true
				ts.Gw.SetConfig(globalConf)

				if err := ts.RemoveApis(); err != nil {
					t.Error("removing apis:" + err.Error())
				}

				ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
					spec.UseKeylessAccess = false
					spec.Proxy.ListenPath = "/"
					spec.CacheOptions = apidef.CacheOptions{
						CacheTimeout:         120,
						EnableCache:          true,
						CacheAllSafeRequests: true,
					}
				})

				key := CreateSession(ts.Gw)

				authHeaders := map[string]string{
					"authorization": key,
				}

				_, err := ts.Run(t, []test.TestCase{
					{Path: "/", Headers: authHeaders, Code: 200},
					{Path: "/", Headers: authHeaders, Code: 200},
				}...)
				if err != nil {
					t.Error("Error executing test case")
				}

				// let records to be sent
				ts.Gw.Analytics.Flush()

				results := ts.Gw.Analytics.Store.GetAndDeleteSet(redisAnalyticsKeyName)
				if len(results) != 2 {
					t.Fatal("Should return 2 records: ", len(results))
				}

				// Take second cached request
				var record analytics.AnalyticsRecord
				err = ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[1].(string)), &record)
				if err != nil {
					t.Error("Error decoding analytics")
				}
				if record.ResponseCode != 200 {
					t.Error("Analytics record do not match", record)
				}

				if record.RawRequest == "" {
					t.Error("Detailed request info not found", record)
				}

				if record.RawResponse == "" {
					t.Error("Detailed response info not found", record)
				}
			})

		})
	}

}

func TestGeoIPLookup(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	testCases := [...]struct {
		in      string
		wantErr bool
	}{
		{"", false},
		{"foobar", true},
		{"1.2.3.4", false},
	}
	for _, tc := range testCases {
		_, err := analytics.GeoIPLookup(tc.in, ts.Gw.Analytics.GeoIPDB)
		switch {
		case tc.wantErr && err == nil:
			t.Errorf("geoIPLookup(%q) did not error", tc.in)
		case !tc.wantErr && err != nil:
			t.Errorf("geoIPLookup(%q) errored", tc.in)
		}
	}
}

func TestURLReplacer(t *testing.T) {

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.NormaliseUrls.Enabled = true
		globalConf.AnalyticsConfig.NormaliseUrls.NormaliseUUIDs = true
		globalConf.AnalyticsConfig.NormaliseUrls.NormaliseNumbers = true
		globalConf.AnalyticsConfig.NormaliseUrls.Custom = []string{"ihatethisstring"}
	})
	defer ts.Close()
	globalConf := ts.Gw.GetConfig()

	recordUUID1 := analytics.AnalyticsRecord{Path: "/15873a748894492162c402d67e92283b/search"}
	recordUUID2 := analytics.AnalyticsRecord{Path: "/CA761232-ED42-11CE-BACD-00AA0057B223/search"}
	recordUUID3 := analytics.AnalyticsRecord{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
	recordUUID4 := analytics.AnalyticsRecord{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
	recordID1 := analytics.AnalyticsRecord{Path: "/widgets/123456/getParams"}
	recordCust := analytics.AnalyticsRecord{Path: "/widgets/123456/getParams/ihatethisstring"}

	globalConf.AnalyticsConfig.NormaliseUrls.CompiledPatternSet = ts.Gw.initNormalisationPatterns()
	ts.Gw.SetConfig(globalConf)

	NormalisePath(&recordUUID1, &globalConf)
	NormalisePath(&recordUUID2, &globalConf)
	NormalisePath(&recordUUID3, &globalConf)
	NormalisePath(&recordUUID4, &globalConf)
	NormalisePath(&recordID1, &globalConf)
	NormalisePath(&recordCust, &globalConf)

	if recordUUID1.Path != "/{uuid}/search" {
		t.Error("Path not altered, is:")
		t.Error(recordUUID1.Path)
		t.Error(ts.Gw.GetConfig().AnalyticsConfig.NormaliseUrls)
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
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.NormaliseUrls.Enabled = true
		globalConf.AnalyticsConfig.NormaliseUrls.NormaliseUUIDs = true
		globalConf.AnalyticsConfig.NormaliseUrls.NormaliseNumbers = true
		globalConf.AnalyticsConfig.NormaliseUrls.Custom = []string{"ihatethisstring"}
	})
	defer ts.Close()

	globalConf := ts.Gw.GetConfig()
	globalConf.AnalyticsConfig.NormaliseUrls.CompiledPatternSet = ts.Gw.initNormalisationPatterns()
	ts.Gw.SetConfig(globalConf)

	for i := 0; i < b.N; i++ {
		recordUUID1 := analytics.AnalyticsRecord{Path: "/15873a748894492162c402d67e92283b/search"}
		recordUUID2 := analytics.AnalyticsRecord{Path: "/CA761232-ED42-11CE-BACD-00AA0057B223/search"}
		recordUUID3 := analytics.AnalyticsRecord{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
		recordUUID4 := analytics.AnalyticsRecord{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
		recordID1 := analytics.AnalyticsRecord{Path: "/widgets/123456/getParams"}
		recordCust := analytics.AnalyticsRecord{Path: "/widgets/123456/getParams/ihatethisstring"}

		NormalisePath(&recordUUID1, &globalConf)
		NormalisePath(&recordUUID2, &globalConf)
		NormalisePath(&recordUUID3, &globalConf)
		NormalisePath(&recordUUID4, &globalConf)
		NormalisePath(&recordID1, &globalConf)
		NormalisePath(&recordCust, &globalConf)
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
