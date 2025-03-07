package gateway

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
	"github.com/TykTechnologies/tyk/user"
)

func TestAnalytics_Write(t *testing.T) {
	test.Flaky(t)
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
				assert.Equal(t, 2, len(results), "Should return 2 records")

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

				// Since we changed config, we need to force all APIs be reloaded
				ts.Gw.BuildAndLoadAPI()

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
				assert.Equal(t, 2, len(results))

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

			t.Run("Upstream error analytics", func(t *testing.T) {
				defer func() {
					ts.Gw.SetConfig(base)
				}()
				ls := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					time.Sleep(2 * time.Millisecond)
					w.WriteHeader(http.StatusOK)
				}))
				defer ls.Close()

				ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
					spec.UseKeylessAccess = false
					spec.Proxy.ListenPath = "/"
					spec.Proxy.TargetURL = ls.URL
				})

				key := CreateSession(ts.Gw)

				authHeaders := map[string]string{
					"authorization": key,
				}

				client := http.Client{
					Timeout: 1 * time.Millisecond,
				}
				_, err := ts.Run(t, test.TestCase{
					Path: "/", Headers: authHeaders, Code: 499, Client: &client, ErrorMatch: "context deadline exceeded",
				})
				assert.NotNil(t, err)

				// we wait until the request finish
				time.Sleep(3 * time.Millisecond)
				// let records to to be sent
				ts.Gw.Analytics.Flush()

				results := ts.Gw.Analytics.Store.GetAndDeleteSet(redisAnalyticsKeyName)
				assert.Len(t, results, 1)

				var record analytics.AnalyticsRecord
				err = ts.Gw.Analytics.analyticsSerializer.Decode([]byte(results[0].(string)), &record)
				assert.Nil(t, err)

				// expect a status 499 (context canceled) from the request
				assert.Equal(t, 499, record.ResponseCode)
				// expect that the analytic record maintained the APIKey
				assert.Equal(t, key, record.APIKey)

			})
			t.Run("Chunked response analytics", func(t *testing.T) {
				defer func() {
					ts.Gw.SetConfig(base)
				}()
				globalConf := ts.Gw.GetConfig()
				globalConf.AnalyticsConfig.EnableDetailedRecording = true
				ts.Gw.SetConfig(globalConf)

				// Since we changed config, we need to force all APIs be reloaded
				ts.Gw.BuildAndLoadAPI()

				ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
					spec.UseKeylessAccess = false
					spec.Proxy.ListenPath = "/"
				})

				key := CreateSession(ts.Gw)

				authHeaders := map[string]string{
					"authorization": key,
				}

				_, err := ts.Run(t, test.TestCase{
					Path: "/chunked", Headers: authHeaders, Code: 200,
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

				rawResponse, err := base64.StdEncoding.DecodeString(record.RawResponse)
				if err != nil {
					t.Error("error decoding response")
				}

				decoded := string(rawResponse)
				if strings.Contains(decoded, "1a") {
					t.Error("Response should not have chunked characters")
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

func TestWebsocketAnalytics(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	globalConf := ts.Gw.GetConfig()
	globalConf.HttpServerOptions.EnableWebSockets = true
	globalConf.Streaming.EnableWebSocketDetailedRecording = true
	globalConf.AnalyticsConfig.EnableDetailedRecording = true
	ts.Gw.SetConfig(globalConf)

	// Create a session with a rate limit of 5 requests per second
	session := CreateSession(ts.Gw, func(s *user.SessionState) {
		s.Rate = 5
		s.Per = 1
		s.QuotaMax = -1
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/"
		spec.UseKeylessAccess = false
	})

	baseURL := strings.Replace(ts.URL, "http://", "ws://", -1)

	// Function to create a new WebSocket connection
	dialWS := func() (*websocket.Conn, *http.Response, error) {
		headers := http.Header{"Authorization": {session}}
		return websocket.DefaultDialer.Dial(baseURL+"/ws", headers)
	}

	// Cleanup before the test
	ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

	// Connect and send messages
	conn, _, err := dialWS()
	if err != nil {
		t.Fatalf("cannot make websocket connection: %v", err)
	}

	// Send and receive 3 messages
	for i := 0; i < 3; i++ {
		err = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("test message %d", i+1)))
		if err != nil {
			t.Fatalf("cannot write message: %v", err)
		}

		_, _, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("cannot read message: %v", err)
		}
	}

	conn.Close()

	time.Sleep(100 * time.Millisecond)

	// Flush analytics
	ts.Gw.Analytics.Flush()

	time.Sleep(100 * time.Millisecond)

	// Retrieve analytics records
	analyticsRecords := ts.Gw.Analytics.Store.GetAndDeleteSet(analyticsKeyName)

	// We expect 1 record for the initial handshake, and 3 records each for requests and responses
	expectedRecords := 7
	if len(analyticsRecords) != expectedRecords {
		t.Errorf("Expected %d analytics records, got %d", expectedRecords, len(analyticsRecords))
	}

	// Verify the content of the analytics records
	var handshakeFound bool
	var requestCount, responseCount int

	for _, record := range analyticsRecords {
		var analyticRecord analytics.AnalyticsRecord
		err := ts.Gw.Analytics.analyticsSerializer.Decode([]byte(record.(string)), &analyticRecord)
		if err != nil {
			t.Errorf("Error decoding analytics record: %v", err)
			continue
		}

		// Check for handshake record
		if analyticRecord.Path == "/ws" && analyticRecord.Method == "GET" {
			handshakeFound = true
		}

		// Check for WebSocket message records
		if strings.Contains(analyticRecord.Path, "/ws") {
			if strings.HasSuffix(analyticRecord.Path, "/in") {
				requestCount++
				if analyticRecord.RawRequest == "" {
					t.Errorf("Request body is empty for request record: %+v", analyticRecord)
				}
				rawResponse, _ := base64.StdEncoding.DecodeString(analyticRecord.RawResponse)
				if !strings.Contains(string(rawResponse), "Content-Length: 0") {
					t.Errorf("Response should contain Content-Length header for request record. Got: %s", rawResponse)
				}
			} else if strings.HasSuffix(analyticRecord.Path, "/out") {
				responseCount++
				if analyticRecord.RawResponse == "" {
					t.Errorf("Response body is empty for response record: %+v", analyticRecord)
				}
				rawRequest, _ := base64.StdEncoding.DecodeString(analyticRecord.RawRequest)
				if strings.Contains(string(rawRequest), "Content-Length") {
					t.Errorf("Request should  notcontain Content-Length header for response record. Got: %s", rawRequest)
				}
			}
		}
	}

	if !handshakeFound {
		t.Error("Handshake record not found in analytics")
	}

	if requestCount != 3 {
		t.Errorf("Expected 3 WebSocket request records, got %d", requestCount)
	}

	if responseCount != 3 {
		t.Errorf("Expected 3 WebSocket response records, got %d", responseCount)
	}
}

func TestURLReplacer(t *testing.T) {

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.AnalyticsConfig.NormaliseUrls.Enabled = true
		globalConf.AnalyticsConfig.NormaliseUrls.NormaliseUUIDs = true
		globalConf.AnalyticsConfig.NormaliseUrls.NormaliseULIDs = true
		globalConf.AnalyticsConfig.NormaliseUrls.NormaliseNumbers = true
		globalConf.AnalyticsConfig.NormaliseUrls.Custom = []string{"ihatethisstring"}
	})
	defer ts.Close()
	globalConf := ts.Gw.GetConfig()

	recordUUID1 := analytics.AnalyticsRecord{Path: "/15873a748894492162c402d67e92283b/search"}
	recordUUID2 := analytics.AnalyticsRecord{Path: "/CA761232-ED42-11CE-BACD-00AA0057B223/search"}
	recordUUID3 := analytics.AnalyticsRecord{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
	recordUUID4 := analytics.AnalyticsRecord{Path: "/ca761232-ed42-11ce-BAcd-00aa0057b223/search"}
	recordULID1 := analytics.AnalyticsRecord{Path: "/posts/01G9HHNKWGBHCQX7VG3JKSZ055/comments"}
	recordULID2 := analytics.AnalyticsRecord{Path: "/posts/01g9hhnkwgbhcqx7vg3jksz055/comments"}
	recordULID3 := analytics.AnalyticsRecord{Path: "/posts/01g9HHNKwgbhcqx7vg3JKSZ055/comments"}
	recordID1 := analytics.AnalyticsRecord{Path: "/widgets/123456/getParams"}
	recordCust := analytics.AnalyticsRecord{Path: "/widgets/123456/getParams/ihatethisstring"}

	globalConf.AnalyticsConfig.NormaliseUrls.CompiledPatternSet = ts.Gw.initNormalisationPatterns()
	ts.Gw.SetConfig(globalConf)

	NormalisePath(&recordUUID1, &globalConf)
	NormalisePath(&recordUUID2, &globalConf)
	NormalisePath(&recordUUID3, &globalConf)
	NormalisePath(&recordUUID4, &globalConf)
	NormalisePath(&recordULID1, &globalConf)
	NormalisePath(&recordULID2, &globalConf)
	NormalisePath(&recordULID3, &globalConf)
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

	assert.Equal(t, "/posts/{ulid}/comments", recordULID1.Path, "Path not altered, is: ", recordULID1.Path)
	assert.Equal(t, "/posts/{ulid}/comments", recordULID2.Path, "Path not altered, is: ", recordULID2.Path)
	assert.Equal(t, "/posts/{ulid}/comments", recordULID3.Path, "Path not altered, is: ", recordULID3.Path)

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
		globalConf.AnalyticsConfig.NormaliseUrls.NormaliseULIDs = true
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
		recordULID1 := analytics.AnalyticsRecord{Path: "/posts/01G9HHNKWGBHCQX7VG3JKSZ055/comments"}
		recordULID2 := analytics.AnalyticsRecord{Path: "/posts/01g9hhnkwgbhcqx7vg3jksz055/comments"}
		recordULID3 := analytics.AnalyticsRecord{Path: "/posts/01g9HHNKwgbhcqx7vg3JKSZ055/comments"}
		recordID1 := analytics.AnalyticsRecord{Path: "/widgets/123456/getParams"}
		recordCust := analytics.AnalyticsRecord{Path: "/widgets/123456/getParams/ihatethisstring"}

		NormalisePath(&recordUUID1, &globalConf)
		NormalisePath(&recordUUID2, &globalConf)
		NormalisePath(&recordUUID3, &globalConf)
		NormalisePath(&recordUUID4, &globalConf)
		NormalisePath(&recordULID1, &globalConf)
		NormalisePath(&recordULID2, &globalConf)
		NormalisePath(&recordULID3, &globalConf)
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
