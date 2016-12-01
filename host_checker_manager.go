package main

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"github.com/TykTechnologies/logrus"
	"github.com/lonelycode/go-uuid/uuid"
	"github.com/TykTechnologies/tykcommon"
	"gopkg.in/vmihailenco/msgpack.v2"
	"net/url"
	"time"
)

var GlobalHostChecker HostCheckerManager

type HostCheckerManager struct {
	Id                string
	store             *RedisClusterStorageManager
	checker           *HostUptimeChecker
	stopLoop          bool
	pollerStarted     bool
	unhealthyHostList map[string]bool
	currentHostList   map[string]HostData
	resetsInitiated   map[string]bool
}

type UptimeReportData struct {
	URL          string
	RequestTime  int64
	ResponseCode int
	TCPError     bool
	ServerError  bool
	Day          int
	Month        time.Month
	Year         int
	Hour         int
	Minute       int
	TimeStamp    time.Time
	ExpireAt     time.Time `bson:"expireAt" json:"expireAt"`
	APIID        string
	OrgID        string
}

func (u *UptimeReportData) SetExpiry(expiresInSeconds int64) {
	var expiry time.Duration

	expiry = time.Duration(expiresInSeconds) * time.Second

	if expiresInSeconds == 0 {
		// Expiry is set to 100 years
		expiry = (24 * time.Hour) * (365 * 100)
	}

	t := time.Now()
	t2 := t.Add(expiry)
	u.ExpireAt = t2
}

const (
	UnHealthyHostMetaDataTargetKey string = "target_url"
	UnHealthyHostMetaDataAPIKey    string = "api_id"
	UnHealthyHostMetaDataHostKey   string = "host_name"
	PollerCacheKey                 string = "PollerActiveInstanceID"
	PoolerHostSentinelKeyPrefix    string = "PollerCheckerInstance:"

	UptimeAnalytics_KEYNAME string = "tyk-uptime-analytics"
)

func (hc *HostCheckerManager) Init(store *RedisClusterStorageManager) {
	hc.store = store
	hc.unhealthyHostList = make(map[string]bool)
	hc.resetsInitiated = make(map[string]bool)
	// Generate a new ID for ourselves
	hc.GenerateCheckerId()
}

func (hc *HostCheckerManager) Start() {
	// Start loop to check if we are active instance
	if hc.Id != "" {
		go hc.CheckActivePollerLoop()
		if config.UptimeTests.Config.EnableUptimeAnalytics {
			go hc.UptimePurgeLoop()
		}
	}
}

func (hc *HostCheckerManager) GenerateCheckerId() {
	hc.Id = uuid.NewUUID().String()
}

func (hc *HostCheckerManager) CheckActivePollerLoop() {
	for {
		if hc.stopLoop {
			log.WithFields(logrus.Fields{
				"prefix": "host-check-mgr",
			}).Debug("Stopping uptime tests")
			break
		}

		// If I'm polling, lets start the loop
		if hc.AmIPolling() {
			if !hc.pollerStarted {
				log.WithFields(logrus.Fields{
					"prefix": "host-check-mgr",
				}).Info("Starting Poller")
				hc.pollerStarted = true
				go hc.StartPoller()
			}
		} else {
			log.WithFields(logrus.Fields{
				"prefix": "host-check-mgr",
			}).Debug("New master found, no tests running")
			if hc.pollerStarted {
				go hc.StopPoller()
				hc.pollerStarted = false
			}
		}

		time.Sleep(10 * time.Second)
	}
}

func (hc *HostCheckerManager) UptimePurgeLoop() {}

func (hc *HostCheckerManager) AmIPolling() bool {
	if hc.store == nil {
		log.WithFields(logrus.Fields{
			"prefix": "host-check-mgr",
		}).Error("No storage instance set for uptime tests! Disabling poller...")
		return false
	}
	ActiveInstance, err := hc.store.GetKey(PollerCacheKey)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "host-check-mgr",
		}).Debug("No Primary instance found, assuming control")
		hc.store.SetKey(PollerCacheKey, hc.Id, 15)
		return true
	}

	if ActiveInstance == hc.Id {
		log.WithFields(logrus.Fields{
			"prefix": "host-check-mgr",
		}).Debug("Primary instance set, I am master")
		hc.store.SetKey(PollerCacheKey, hc.Id, 15) // Reset TTL
		return true
	}

	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Debug("Active Instance is: ", ActiveInstance)
	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Debug("--- I am: ", hc.Id)

	return false
}

func (hc *HostCheckerManager) StartPoller() {

	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Debug("---> Initialising checker")

	// If we are restarting, we want to retain the host list
	if hc.checker == nil {
		hc.checker = &HostUptimeChecker{}
	}

	hc.checker.Init(config.UptimeTests.Config.CheckerPoolSize,
		config.UptimeTests.Config.FailureTriggerSampleSize,
		config.UptimeTests.Config.TimeWait,
		hc.currentHostList,
		hc.OnHostDown,   // On failure
		hc.OnHostBackUp, // On success
		hc.OnHostReport) // All reports

	// Start the check loop
	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Debug("---> Starting checker")
	hc.checker.Start()
	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Debug("---> Checker started.")
}

func (hc *HostCheckerManager) StopPoller() {
	if hc.checker != nil {
		hc.checker.Stop()
	}
}

func (hc *HostCheckerManager) getHostKey(report HostHealthReport) string {
	return PoolerHostSentinelKeyPrefix + report.MetaData[UnHealthyHostMetaDataHostKey]
}

func (hc *HostCheckerManager) OnHostReport(report HostHealthReport) {
	if config.UptimeTests.Config.EnableUptimeAnalytics {
		go hc.RecordUptimeAnalytics(report)
	}
}

func (hc *HostCheckerManager) OnHostDown(report HostHealthReport) {
	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Debug("Update key: ", hc.getHostKey(report))
	hc.store.SetKey(hc.getHostKey(report), "1", int64(config.UptimeTests.Config.TimeWait + 1))

	thisSpec, found := (*ApiSpecRegister)[report.MetaData[UnHealthyHostMetaDataAPIKey]]
	if !found {
		log.WithFields(logrus.Fields{
			"prefix": "host-check-mgr",
		}).Warning("[HOST CHECKER MANAGER] Event can't fire for API that doesn't exist")
		return
	}

	go thisSpec.FireEvent(EVENT_HOSTDOWN,
		EVENT_HostStatusMeta{
			EventMetaDefault: EventMetaDefault{Message: "Uptime test failed"},
			HostInfo:         report,
		})

	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Warning("[HOST CHECKER MANAGER] Host is DOWN: ", report.CheckURL)

	if thisSpec.UptimeTests.Config.ServiceDiscovery.UseDiscoveryService {
		thisApiId := thisSpec.APIID

		// only do this once
		_, initiated := hc.resetsInitiated[thisApiId]
		if !initiated {
			hc.resetsInitiated[thisApiId] = true
			// Lets re-check the uptime tests after x seconds
			go func() {
				log.WithFields(logrus.Fields{
					"prefix": "host-check-mgr",
				}).Printf("[HOST CHECKER MANAGER] Resetting test host list in %v seconds for API: %v", thisSpec.UptimeTests.Config.RecheckWait, thisApiId)
				time.Sleep(time.Duration(thisSpec.UptimeTests.Config.RecheckWait) * time.Second)
				hc.DoServiceDiscoveryListUpdateForID(thisApiId)
				delete(hc.resetsInitiated, thisApiId)
			}()
		}
	}
}

func (hc *HostCheckerManager) OnHostBackUp(report HostHealthReport) {
	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Debug("Delete key: ", hc.getHostKey(report))
	hc.store.DeleteKey(hc.getHostKey(report))

	thisSpec, found := (*ApiSpecRegister)[report.MetaData[UnHealthyHostMetaDataAPIKey]]
	if !found {
		log.WithFields(logrus.Fields{
			"prefix": "host-check-mgr",
		}).Warning("[HOST CHECKER MANAGER] Event can't fire for API that doesn't exist")
		return
	}
	go thisSpec.FireEvent(EVENT_HOSTUP,
		EVENT_HostStatusMeta{
			EventMetaDefault: EventMetaDefault{Message: "Uptime test suceeded"},
			HostInfo:         report,
		})

	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Warning("[HOST CHECKER MANAGER] Host is UP:   ", report.CheckURL)
}

func (hc *HostCheckerManager) IsHostDown(thisUrl string) bool {
	u, err := url.Parse(thisUrl)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "host-check-mgr",
		}).Error(err)
	}

	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Debug("Key is: ", PoolerHostSentinelKeyPrefix+u.Host)
	_, fErr := hc.store.GetKey(PoolerHostSentinelKeyPrefix + u.Host)

	if fErr != nil {
		// Found a key, the host is down
		return true
	}

	return false
}

func (hc *HostCheckerManager) PrepareTrackingHost(checkObject tykcommon.HostCheckObject, APIID string) (HostData, error) {
	// Build the check URL:
	var thisHostData HostData
	u, err := url.Parse(checkObject.CheckURL)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "host-check-mgr",
		}).Error(err)
		return thisHostData, err
	}

	var bodyData string
	var bodyByteArr []byte
	var loadErr error
	if len(checkObject.Body) > 0 {
		bodyByteArr, loadErr = b64.StdEncoding.DecodeString(checkObject.Body)
		if loadErr != nil {
			log.WithFields(logrus.Fields{
				"prefix": "host-check-mgr",
			}).Error("Failed to load blob data: ", loadErr)
			return thisHostData, loadErr
		}
		bodyData = string(bodyByteArr)
	}

	thisHostData = HostData{
		CheckURL: checkObject.CheckURL,
		ID:       checkObject.CheckURL,
		MetaData: make(map[string]string),
		Method:   checkObject.Method,
		Headers:  checkObject.Headers,
		Body:     bodyData,
	}

	// Add our specific metadata
	thisHostData.MetaData[UnHealthyHostMetaDataTargetKey] = checkObject.CheckURL
	thisHostData.MetaData[UnHealthyHostMetaDataAPIKey] = APIID
	thisHostData.MetaData[UnHealthyHostMetaDataHostKey] = u.Host

	return thisHostData, nil
}

func (hc *HostCheckerManager) UpdateTrackingList(hd []HostData) {
	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Debug("--- Setting tracking list up")
	newHostList := make(map[string]HostData)
	for _, host := range hd {
		newHostList[host.CheckURL] = host
	}

	hc.currentHostList = newHostList
	if hc.checker != nil {
		log.WithFields(logrus.Fields{
			"prefix": "host-check-mgr",
		}).Debug("Reset initiated")
		hc.checker.ResetList(&newHostList)
	}
}

func (hc *HostCheckerManager) UpdateTrackingListByAPIID(hd []HostData, apiId string) {
	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Debug("--- Setting tracking list up for ID: ", apiId)
	newHostList := make(map[string]HostData)

	for _, existingHost := range hc.currentHostList {
		if existingHost.MetaData[UnHealthyHostMetaDataAPIKey] != apiId {
			// Add the old check list that excludes this API
			newHostList[existingHost.CheckURL] = existingHost
		}
	}

	// Add the new list for this APIID:
	for _, host := range hd {
		newHostList[host.CheckURL] = host
	}

	hc.currentHostList = newHostList
	if hc.checker != nil {
		log.WithFields(logrus.Fields{
			"prefix": "host-check-mgr",
		}).Debug("Reset initiated")
		hc.checker.ResetList(&newHostList)
	}
	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Info("--- Queued tracking list update for API: ", apiId)
}

func (hc *HostCheckerManager) GetListFromService(APIID string) ([]HostData, error) {
	spec, found := (*ApiSpecRegister)[APIID]
	if !found {
		return []HostData{}, errors.New("API ID not found in register!")
	}
	sd := ServiceDiscovery{}
	sd.New(&spec.UptimeTests.Config.ServiceDiscovery)
	data, err := sd.GetTarget(spec.UptimeTests.Config.ServiceDiscovery.QueryEndpoint)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "host-check-mgr",
		}).Error("[HOST CHECKER MANAGER] Failed to retrieve host list: ", err)
		return []HostData{}, err
	}

	// The returned data is a string, so lets unmarshal it:
	checkTargets := make([]tykcommon.HostCheckObject, 0)
	thisData, _ := data.GetIndex(0)
	decodeErr := json.Unmarshal([]byte(thisData), &checkTargets)

	if decodeErr != nil {
		log.WithFields(logrus.Fields{
			"prefix": "host-check-mgr",
		}).Error("[HOST CHECKER MANAGER] Decoder failed: ", decodeErr)
		return []HostData{}, decodeErr
	}

	thisHostData := make([]HostData, len(checkTargets))
	for i, target := range checkTargets {
		newHostDoc, hdGenErr := GlobalHostChecker.PrepareTrackingHost(target, spec.APIID)
		if hdGenErr != nil {
			log.WithFields(logrus.Fields{
				"prefix": "host-check-mgr",
			}).Error("[HOST CHECKER MANAGER] failed to convert to HostData", err)
		} else {
			thisHostData[i] = newHostDoc
		}
	}
	return thisHostData, nil
}

func (hc *HostCheckerManager) DoServiceDiscoveryListUpdateForID(APIID string) {
	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Debug("[HOST CHECKER MANAGER] Getting data from service")
	hostData, err := hc.GetListFromService(APIID)
	if err != nil {
		return
	}

	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Debug("[HOST CHECKER MANAGER] Data was: \n", hostData)
	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Info("[HOST CHECKER MANAGER] Refreshing uptime tests from service for API: ", APIID)
	hc.UpdateTrackingListByAPIID(hostData, APIID)
}

// RecordHit will store an AnalyticsRecord in Redis
func (hc HostCheckerManager) RecordUptimeAnalytics(thisReport HostHealthReport) error {
	// If we are obfuscating API Keys, store the hashed representation (config check handled in hashing function)

	thisSpec, found := (*ApiSpecRegister)[thisReport.MetaData[UnHealthyHostMetaDataAPIKey]]
	thisOrg := ""
	if found {
		thisOrg = thisSpec.OrgID
	}

	t := time.Now()

	var serverError bool
	if thisReport.ResponseCode > 200 {
		serverError = true
	}

	newAnalyticsRecord := UptimeReportData{
		URL:          thisReport.CheckURL,
		RequestTime:  int64(thisReport.Latency),
		ResponseCode: thisReport.ResponseCode,
		TCPError:     thisReport.IsTCPError,
		ServerError:  serverError,
		Day:          t.Day(),
		Month:        t.Month(),
		Year:         t.Year(),
		Hour:         t.Hour(),
		Minute:       t.Minute(),
		TimeStamp:    t,
		APIID:        thisReport.MetaData[UnHealthyHostMetaDataAPIKey],
		OrgID:        thisOrg,
	}

	// For anlytics purposes, we need a code
	if thisReport.IsTCPError {
		newAnalyticsRecord.ResponseCode = 521
	}

	newAnalyticsRecord.SetExpiry(thisSpec.UptimeTests.Config.ExpireUptimeAnalyticsAfter)

	encoded, err := msgpack.Marshal(newAnalyticsRecord)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "host-check-mgr",
		}).Error("Error encoding uptime data:", err)
		return err
	}

	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Debug("Recording uptime stat")
	hc.store.AppendToSet(UptimeAnalytics_KEYNAME, string(encoded))
	return nil
}

func InitHostCheckManager(store *RedisClusterStorageManager) {
	GlobalHostChecker = HostCheckerManager{}
	GlobalHostChecker.Init(store)
	GlobalHostChecker.Start()
}

func SetCheckerHostList() {
	log.WithFields(logrus.Fields{
		"prefix": "host-check-mgr",
	}).Info("Loading uptime tests...")
	hostList := []HostData{}
	for _, spec := range *ApiSpecRegister {
		if spec.UptimeTests.Config.ServiceDiscovery.UseDiscoveryService {
			thisHostList, sdErr := GlobalHostChecker.GetListFromService(spec.APIID)
			if sdErr == nil {
				hostList = append(hostList, thisHostList...)
				for _, t := range thisHostList {
					log.WithFields(logrus.Fields{
						"prefix": "host-check-mgr",
					}).WithFields(logrus.Fields{
						"prefix": "host-check-mgr",
					}).Info("---> Adding uptime test: ", t.CheckURL)
				}
			}
		} else {
			for _, checkItem := range spec.UptimeTests.CheckList {
				newHostDoc, hdGenErr := GlobalHostChecker.PrepareTrackingHost(checkItem, spec.APIID)
				if hdGenErr == nil {
					hostList = append(hostList, newHostDoc)
					log.WithFields(logrus.Fields{
						"prefix": "host-check-mgr",
					}).Info("---> Adding uptime test: ", checkItem.CheckURL)
				} else {
					log.WithFields(logrus.Fields{
						"prefix": "host-check-mgr",
					}).Warning("---> Adding uptime test failed: ", checkItem.CheckURL)
					log.WithFields(logrus.Fields{
						"prefix": "host-check-mgr",
					}).Warning("--------> Error was: ", hdGenErr)
				}

			}
		}
	}

	GlobalHostChecker.UpdateTrackingList(hostList)
}

/*

## TEST CONFIGURATION

uptime_tests: {
    check_list: [
      {
        "url": "http://google.com:3000/"
      },
      {
        "url": "http://posttestserver.com/post.php?dir=tyk-checker-target-test&beep=boop",
        "method": "POST",
        "headers": {
          "this": "that",
          "more": "beans"
        },
        "body": "VEhJUyBJUyBBIEJPRFkgT0JKRUNUIFRFWFQNCg0KTW9yZSBzdHVmZiBoZXJl"
      }
    ]
  },

*/
