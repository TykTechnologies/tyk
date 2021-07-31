package gateway

import (
	"context"
	"net/http"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	uuid "github.com/satori/go.uuid"
)

func TestHostCheckerManagerInit(t *testing.T) {

	hc := HostCheckerManager{}
	redisStorage := storage.New(storage.Options{
		KeyPrefix: "host-checker-test:",
	})
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
	hc := HostCheckerManager{}

	polling := hc.AmIPolling()
	if polling {
		t.Error("HostCheckerManager storage not configured, it should have failed.")
	}

	//Testing if we had 2 active host checker managers, only 1 takes control of the uptimechecks
	globalConf := config.Global()
	groupID := "TEST"
	globalConf.UptimeTests.PollerGroup = groupID
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	redisStorage := storage.New(storage.Options{
		KeyPrefix: "host-checker-test:",
	})
	hc.Init(redisStorage)
	hc2 := HostCheckerManager{}
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

	globalConf = config.Global()
	groupID = ""
	globalConf.UptimeTests.PollerGroup = groupID
	config.SetGlobal(globalConf)
	defer ResetTestConfig()

	//Testing if the PollerCacheKey doesn't contains the poller_group by default
	hc = HostCheckerManager{}
	redisStorage = storage.New(storage.Options{
		KeyPrefix: "host-checker-test:",
	})
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
	hc := HostCheckerManager{}
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

	hc := &HostCheckerManager{}
	redisStorage := storage.New(storage.Options{
		KeyPrefix: "host-checker-test-1:",
	})
	hc.Init(redisStorage)

	ctx, cancel := context.WithCancel(context.TODO())
	go hc.CheckActivePollerLoop(ctx)
	defer cancel()

	found := false

	//Giving 15 retries to find the poller active key
	for i := 0; i < 15; i++ {
		activeInstance, err := hc.store.GetKey(PollerCacheKey)
		if activeInstance == hc.Id && err == nil {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("activeInstance should be %q when the CheckActivePollerLoop is running", hc.Id)
	}

}

func TestStartPoller(t *testing.T) {
	hc := HostCheckerManager{}
	redisStorage := storage.New(storage.Options{
		KeyPrefix: "host-checker-TestStartPoller:",
	})
	hc.Init(redisStorage)
	ctx, cancel := context.WithCancel(context.TODO())

	hc.StartPoller(ctx)
	defer cancel()

	if hc.checker == nil {
		t.Error("StartPoller should have initialized the HostUptimeChecker")
	}
}

func TestRecordUptimeAnalytics(t *testing.T) {

	hc := &HostCheckerManager{}
	redisStorage := storage.New(storage.Options{
		KeyPrefix: "host-checker-test-analytics:",
	})
	hc.Init(redisStorage)

	spec := &APISpec{}
	spec.APIDefinition = &apidef.APIDefinition{APIID: "test-analytics"}
	spec.UptimeTests.Config.ExpireUptimeAnalyticsAfter = 30
	apisMu.Lock()
	apisByID = map[string]*APISpec{spec.APIID: spec}
	apisMu.Unlock()

	defer func() {
		apisMu.Lock()
		apisByID = make(map[string]*APISpec)
		apisMu.Unlock()
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
