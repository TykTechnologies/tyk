package gateway

import (
	"net/http"
	"testing"

	uuid "github.com/satori/go.uuid"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/test"
)

func TestHostCheckerManagerInit(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()

	hc := HostCheckerManager{Gw: ts.Gw}
	redisStorage := &storage.RedisCluster{KeyPrefix: "host-checker-test:", RedisController: ts.Gw.RedisController}
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

	redisStorage := &storage.RedisCluster{KeyPrefix: "host-checker-test:", RedisController: ts.Gw.RedisController}
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
	redisStorage = &storage.RedisCluster{KeyPrefix: "host-checker-test:", RedisController: ts.Gw.RedisController}
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

	uuid, _ := uuid.FromString(hc.Id)
	if uuid.Version() != 4 {
		t.Error("HostCheckerManager should generate an uuid.v4 id")
	}
}

func TestCheckActivePollerLoop(t *testing.T) {
	test.Flaky(t) // TODO: TT-5259

	ts := StartTest(nil)
	defer ts.Close()

	hc := &HostCheckerManager{Gw: ts.Gw}
	redisStorage := &storage.RedisCluster{KeyPrefix: "host-checker-test-1:", RedisController: ts.Gw.RedisController}
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
	redisStorage := &storage.RedisCluster{KeyPrefix: "host-checker-TestStartPoller:", RedisController: ts.Gw.RedisController}
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

	redisStorage := &storage.RedisCluster{KeyPrefix: "host-checker-test-analytics:", RedisController: ts.Gw.RedisController}
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
