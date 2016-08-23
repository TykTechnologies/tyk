package main

import (
	"encoding/json"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/TykTechnologies/tykcommon"
	"io/ioutil"
	"time"
)

type GetConfigPayload struct {
	FromHostname string
	FromNodeID   string
	TimeStamp    int64
}

type ReturnConfigPayload struct {
	FromHostname  string
	FromNodeID    string
	Configuration MicroConfig
	TimeStamp     int64
}

// This is what gets sent by the dashboard
type MicroConfig struct {
	EnableAnalytics bool `json:"enable_analytics,omitempty"`
	AnalyticsConfig struct {
		IgnoredIPs              []string `json:"ignored_ips,omitempty"`
		EnableDetailedRecording bool     `json:"enable_detailed_recording,omitempty"`
		EnableGeoIP             bool     `json:"enable_geo_ip,omitempty"`
		GeoIPDBLocation         string   `json:"geo_ip_db_path,omitempty"`
		NormaliseUrls           struct {
			Enabled          bool     `json:"enabled,omitempty"`
			NormaliseUUIDs   bool     `json:"normalise_uuids,omitempty"`
			NormaliseNumbers bool     `json:"normalise_numbers,omitempty"`
			Custom           []string `json:"custom_patterns,omitempty"`
		} `json:"normalise_urls,omitempty"`
	} `json:"analytics_config,omitempty"`
	HealthCheck struct {
		EnableHealthChecks      bool  `json:"enable_health_checks,omitempty"`
		HealthCheckValueTimeout int64 `json:"health_check_value_timeouts,omitempty"`
	} `json:"health_check,omitempty"`
	Monitor struct {
		EnableTriggerMonitors bool               `json:"enable_trigger_monitors,omitempty"`
		Config                WebHookHandlerConf `json:"configuration,omitempty"`
		GlobalTriggerLimit    float64            `json:"global_trigger_limit,omitempty"`
		MonitorUserKeys       bool               `json:"monitor_user_keys,omitempty"`
	}
	EnableCustomDomains bool                             `json:"enable_custom_domains,omitempty"`
	EnableJSVM          bool                             `json:"enable_jsvm,omitempty"`
	EnableCoProcess     bool                             `json:"enable_coprocess,omitempty"`
	EventHandlers       tykcommon.EventHandlerMetaConfig `json:"event_handlers,omitempty"`
}

func GetExistingConfig() (MicroConfig, error) {

	value, _ := argumentsBackup["--conf"]
	thisMicroConfig := MicroConfig{}

	var filename string = "./tyk.conf"
	if value != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Info(fmt.Sprintf("Using %s for configuration", value.(string)))
		filename = argumentsBackup["--conf"].(string)
	} else {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Info("No configuration file defined, will try to use default (./tyk.conf)")
	}

	dat, err := ioutil.ReadFile(filename)
	if err != nil {
		return thisMicroConfig, err
	}

	jsErr := json.Unmarshal(dat, &thisMicroConfig)
	if jsErr != nil {
		return thisMicroConfig, jsErr
	}

	return thisMicroConfig, nil
}

func HandleSendMiniConfig(payload string) {
	// Decode the configuration from the payload
	thisConfigPayload := GetConfigPayload{}

	// Make sure payload matches nodeID and hostname
	if (thisConfigPayload.FromHostname != HostDetails.Hostname) && (thisConfigPayload.FromNodeID != NodeID) {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Info("Configuration request received, no NodeID/Hostname match found, ignoring")
		return
	}

	thisConfig, getConfErr := GetExistingConfig()
	if getConfErr != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to get existing configuration: ", getConfErr)
		return
	}

	returnPayload := ReturnConfigPayload{
		FromHostname:  HostDetails.Hostname,
		FromNodeID:    NodeID,
		Configuration: thisConfig,
		TimeStamp:     time.Now().Unix(),
	}

	payloadAsJSON, jsmErr := json.Marshal(returnPayload)
	if jsmErr != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to get marshal configuration: ", jsmErr)
		return
	}

	asNotification := Notification{
		Command: NoticeGatewayConfigResponse,
		Payload: string(payloadAsJSON),
	}

	MainNotifier.Notify(asNotification)
	log.WithFields(logrus.Fields{
		"prefix": "pub-sub",
	}).Info("Configuration request responded.")

}
