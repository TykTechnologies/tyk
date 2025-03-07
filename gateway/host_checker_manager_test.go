package gateway

import (
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"

	"github.com/stretchr/testify/assert"
)

func TestHostCheckerManagerInit(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	hc := HostCheckerManager{Gw: ts.Gw}

	redisStorage := &storage.RedisCluster{KeyPrefix: "host-checker-test:", ConnectionHandler: ts.Gw.StorageConnectionHandler}
	redisStorage.Connect()

	hc.Init(redisStorage)

	if hc.Id == "" {
		t.Error("HostCheckerManager should create an Id on Init")
	}
	if hc.unhealthyHostList == nil {
		t.Error("HostCheckerManager should initialize unhealthyHostList on Init")
	}
	if hc.resetsInitiated == nil {
		t.Error("HostCheckerManager should initialize resetsInitiated on Init")
	}
}

func TestAmIPolling(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	hc := HostCheckerManager{Gw: ts.Gw}

	polling := hc.AmIPolling()
	if polling {
		t.Error("HostCheckerManager storage not configured, it should have failed.")
	}

	//Testing if we had 2 active host checker managers, only 1 takes control of the uptimechecks
	globalConf := ts.Gw.GetConfig()
	groupID := "TEST"
	globalConf.UptimeTests.PollerGroup = groupID
	ts.Gw.SetConfig(globalConf)

	redisStorage := &storage.RedisCluster{KeyPrefix: "host-checker-test:", ConnectionHandler: ts.Gw.StorageConnectionHandler}
	redisStorage.Connect()

	hc.Init(redisStorage)
	hc2 := HostCheckerManager{Gw: ts.Gw}
	hc2.Init(redisStorage)

	polling = hc.AmIPolling()
	pollingHc2 := hc2.AmIPolling()

	if !polling && pollingHc2 {
		t.Error("HostCheckerManager storage configured, it shouldn't have failed.")
	}

	//Testing if the PollerCacheKey contains the poller_group
	testKey := PollerCacheKey + "." + groupID
	activeInstance, err := hc.store.GetKey(testKey)
	if err != nil {
		t.Errorf("%q  should exist in redis.%v", testKey, activeInstance)
	}
	if activeInstance != hc.Id {
		t.Errorf("%q value : expected %v got %v", testKey, hc.Id, activeInstance)
	}

	globalConf = ts.Gw.GetConfig()
	groupID = ""
	globalConf.UptimeTests.PollerGroup = groupID
	ts.Gw.SetConfig(globalConf)

	//Testing if the PollerCacheKey doesn't contains the poller_group by default
	hc = HostCheckerManager{Gw: ts.Gw}

	redisStorage = &storage.RedisCluster{KeyPrefix: "host-checker-test:", ConnectionHandler: ts.Gw.StorageConnectionHandler}
	redisStorage.Connect()

	hc.Init(redisStorage)
	hc.AmIPolling()

	activeInstance, err = hc.store.GetKey(PollerCacheKey)
	if err != nil {
		t.Errorf("%q should exist in redis.%v", PollerCacheKey, activeInstance)
	}
	if activeInstance != hc.Id {
		t.Errorf("%q : value expected %v got %v", PollerCacheKey, hc.Id, activeInstance)
	}

}

func TestGenerateCheckerId(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	hc := HostCheckerManager{Gw: ts.Gw}
	hc.GenerateCheckerId()
	if hc.Id == "" {
		t.Error("HostCheckerManager should generate an Id on GenerateCheckerId")
	}
}

func TestCheckActivePollerLoop(t *testing.T) {
	test.Flaky(t) // TODO: TT-5259

	ts := StartTest(nil)
	defer ts.Close()

	hc := &HostCheckerManager{Gw: ts.Gw}

	redisStorage := &storage.RedisCluster{KeyPrefix: "host-checker-test-1:", ConnectionHandler: ts.Gw.StorageConnectionHandler}
	redisStorage.Connect()

	hc.Init(redisStorage)

	go hc.CheckActivePollerLoop(ts.Gw.ctx)

	activeInstance, err := redisStorage.GetKey(PollerCacheKey)
	if activeInstance != hc.Id || err != nil {
		t.Errorf("activeInstance should be %q when the CheckActivePollerLoop is running", hc.Id)
	}
}

func TestStartPoller(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	hc := HostCheckerManager{Gw: ts.Gw}

	redisStorage := &storage.RedisCluster{KeyPrefix: "host-checker-TestStartPoller:", ConnectionHandler: ts.Gw.StorageConnectionHandler}
	redisStorage.Connect()

	hc.Init(redisStorage)

	hc.StartPoller(ts.Gw.ctx)

	if hc.checker == nil {
		t.Error("StartPoller should have initialized the HostUptimeChecker")
	}
}

func TestRecordUptimeAnalytics(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	hc := &HostCheckerManager{Gw: ts.Gw}

	redisStorage := &storage.RedisCluster{KeyPrefix: "host-checker-test-analytics:", ConnectionHandler: ts.Gw.StorageConnectionHandler}
	redisStorage.Connect()

	hc.Init(redisStorage)

	spec := &APISpec{}
	spec.APIDefinition = &apidef.APIDefinition{APIID: "test-analytics"}
	spec.UptimeTests.Config.ExpireUptimeAnalyticsAfter = 30
	ts.Gw.apisMu.Lock()
	ts.Gw.apisByID = map[string]*APISpec{spec.APIID: spec}
	ts.Gw.apisMu.Unlock()

	defer func() {
		ts.Gw.apisMu.Lock()
		ts.Gw.apisByID = make(map[string]*APISpec)
		ts.Gw.apisMu.Unlock()
	}()

	hostData := HostData{
		CheckURL: "/test",
		Method:   http.MethodGet,
	}
	report := HostHealthReport{
		HostData:     hostData,
		ResponseCode: http.StatusOK,
		Latency:      10.00,
		IsTCPError:   false,
	}
	report.MetaData = make(map[string]string)
	report.MetaData[UnHealthyHostMetaDataAPIKey] = spec.APIID

	err := hc.RecordUptimeAnalytics(report)
	if err != nil {
		t.Error("RecordUptimeAnalytics shouldn't fail")
	}

	set, err := hc.store.Exists(UptimeAnalytics_KEYNAME)
	if err != nil || !set {
		t.Error("tyk-uptime-analytics should exist in redis.", err)
	}

}

func TestPopulateHostListByApiSpec(t *testing.T) {
	g := StartTest(nil)
	t.Cleanup(g.Close)

	t.Run("enable and disable uptime tests", func(t *testing.T) {
		type testCase struct {
			name             string
			specs            []*APISpec
			expectedHostList []HostData
		}

		testCases := []testCase{
			{
				name: "all enabled",
				specs: []*APISpec{
					{
						APIDefinition: &apidef.APIDefinition{
							UptimeTests: apidef.UptimeTests{
								Disabled: false,
								CheckList: []apidef.HostCheckObject{
									{
										CheckURL: "https://service1.myservices.fake",
										Method:   http.MethodGet,
										Protocol: "https",
										Timeout:  10000,
									},
								},
							},
						},
					},
					{
						APIDefinition: &apidef.APIDefinition{
							UptimeTests: apidef.UptimeTests{
								Disabled: false,
								CheckList: []apidef.HostCheckObject{
									{
										CheckURL: "https://service2.myservices.fake",
										Method:   http.MethodPost,
										Protocol: "https",
										Timeout:  20000,
									},
								},
							},
						},
					},
				},
				expectedHostList: []HostData{
					{
						CheckURL: "https://service1.myservices.fake",
						Method:   http.MethodGet,
						Protocol: "https",
						Timeout:  10000,
					},
					{
						CheckURL: "https://service2.myservices.fake",
						Method:   http.MethodPost,
						Protocol: "https",
						Timeout:  20000,
					},
				},
			},
			{
				name: "only APIs with uptime tests enabled",
				specs: []*APISpec{
					{
						APIDefinition: &apidef.APIDefinition{
							UptimeTests: apidef.UptimeTests{
								Disabled: true,
								CheckList: []apidef.HostCheckObject{
									{
										CheckURL: "https://service1.myservices.fake",
										Method:   http.MethodGet,
										Protocol: "https",
										Timeout:  10000,
									},
								},
							},
						},
					},
					{
						APIDefinition: &apidef.APIDefinition{
							UptimeTests: apidef.UptimeTests{
								Disabled: false,
								CheckList: []apidef.HostCheckObject{
									{
										CheckURL: "https://service2.myservices.fake",
										Method:   http.MethodPost,
										Protocol: "https",
										Timeout:  20000,
									},
								},
							},
						},
					},
				},
				expectedHostList: []HostData{
					{
						CheckURL: "https://service2.myservices.fake",
						Method:   http.MethodPost,
						Protocol: "https",
						Timeout:  20000,
					},
				},
			},
		}

		for _, tc := range testCases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				var actualHostList []HostData
				for _, spec := range tc.specs {
					g.Gw.populateHostListByApiSpec(&actualHostList, spec)
				}

				// The generated metadata map is not relevant for the test cases.
				// It's better to remove it to keep the tests clean.
				for i := range actualHostList {
					actualHostList[i].MetaData = nil
				}

				assert.Equal(t, tc.expectedHostList, actualHostList)
			})
		}
	})
}
