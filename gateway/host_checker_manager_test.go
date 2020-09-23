package gateway

import (
	"bytes"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	uuid "github.com/satori/go.uuid"
	"net/http"
	"testing"
	"text/template"
)

func TestHostCheckerManagerInit(t *testing.T) {
	ts := StartTest()
	defer ts.Close()

	hc := HostCheckerManager{}
	redisStorage := &storage.RedisCluster{KeyPrefix: "host-checker:"}
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

	pooling := hc.AmIPolling()
	if pooling {
		t.Error("HostCheckerManager storage not configured, it should have failed.")
	}

	//Testing if we had 2 active host checker managers, only 1 takes control of the uptimechecks
	globalConf := config.Global()
	globalConf.UptimeTests.PollerGroup = "TEST"
	config.SetGlobal(globalConf)

	ts := StartTest()
	defer ts.Close()

	redisStorage := &storage.RedisCluster{KeyPrefix: "host-checker:"}
	hc.Init(redisStorage)
	hc2 := HostCheckerManager{}
	hc2.Init(redisStorage)

	pooling = hc.AmIPolling()
	poolingHc2 := hc2.AmIPolling()
	if !pooling && poolingHc2 {
		t.Error("HostCheckerManager storage configured, it shouldn't have failed.")
	}

	//Testing if the PollerCacheKey contains the poller_group
	activeInstance, err := hc.store.GetKey("PollerActiveInstanceID.TEST")
	if err != nil {
		t.Error("PollerActiveInstanceID.TEST  should exist in redis.", activeInstance)
	}
	if activeInstance != hc.Id {
		t.Error("PollerActiveInstanceID.TEST value should be hc.Id")
	}

	//Testing if the PollerCacheKey doesn't contains the poller_group by default
	ResetTestConfig()
	emptyRedis()
	hc = HostCheckerManager{}

	redisStorage = &storage.RedisCluster{KeyPrefix: "host-checker:"}
	hc.Init(redisStorage)
	hc.AmIPolling()

	activeInstance, err = hc.store.GetKey("PollerActiveInstanceID")
	if err != nil {
		t.Error("PollerActiveInstanceID should exist in redis.", activeInstance)
	}
	if activeInstance != hc.Id {
		t.Error("PollerActiveInstanceID value should be hc.Id")
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
	ts := StartTest()
	defer ts.Close()
	emptyRedis()

	hc := &HostCheckerManager{}
	redisStorage := &storage.RedisCluster{KeyPrefix: "host-checker:"}
	hc.Init(redisStorage)
	//defering the stop of the CheckActivePollerLoop
	defer func(hc *HostCheckerManager) {
		hc.stopLoop = true
	}(hc)

	go hc.CheckActivePollerLoop()

	found := false

	//Giving 5 retries to find the poller active key
	for i := 0; i < 5; i++ {
		activeInstance, err := hc.store.GetKey("PollerActiveInstanceID")
		if activeInstance == hc.Id && err == nil {
			found = true
			break
		}
	}

	if !found {
		t.Error("activeInstance should be hc.Id when the CheckActivePollerLoop is running")
	}

}

func TestStartPoller(t *testing.T) {
	hc := HostCheckerManager{}
	hc.StartPoller()

	if hc.checker == nil {
		t.Error("StartPoller should have initialized the HostUptimeChecker")
	}
}

func TestRecordUptimeAnalytics(t *testing.T) {
	ts := StartTest()
	defer ts.Close()
	emptyRedis()

	hc := &HostCheckerManager{}
	redisStorage := &storage.RedisCluster{KeyPrefix: "host-checker:"}
	hc.Init(redisStorage)

	specTmpl := template.Must(template.New("spec").Parse(sampleUptimeTestAPI))

	tmplData := struct {
		Host1, Host2 string
	}{
		testHttpFailureAny,
		testHttpFailureAny,
	}

	specBuf := &bytes.Buffer{}
	specTmpl.ExecuteTemplate(specBuf, specTmpl.Name(), &tmplData)

	spec := CreateDefinitionFromString(specBuf.String())
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
