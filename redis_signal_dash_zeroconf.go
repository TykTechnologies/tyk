package main

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"
)

type DashboardConfigPayload struct {
	DashboardConfig struct {
		Hostname string
		Port     int
		UseTLS   bool
	}
	TimeStamp int64
}

func createConnectionStringFromDashboardObject(config DashboardConfigPayload) string {
	hostname := "http://"
	if config.DashboardConfig.UseTLS {
		hostname = "https://"
	}

	hostname = hostname + config.DashboardConfig.Hostname

	if config.DashboardConfig.Port != 0 {
		hostname = strings.TrimRight(hostname, "/")
		hostname = hostname + ":" + strconv.Itoa(config.DashboardConfig.Port)
	}

	return hostname
}

func handleDashboardZeroConfMessage(payload string) {
	// Decode the configuration from the payload
	dashPayload := DashboardConfigPayload{}
	err := json.Unmarshal([]byte(payload), &dashPayload)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to decode dashboard zeroconf payload")
		return
	}

	if !globalConf.UseDBAppConfigs {
		return
	}

	if globalConf.DisableDashboardZeroConf {
		return
	}

	hostname := createConnectionStringFromDashboardObject(dashPayload)
	setHostname := false
	if globalConf.DBAppConfOptions.ConnectionString == "" {
		globalConf.DBAppConfOptions.ConnectionString = hostname
		setHostname = true
	}

	if globalConf.Policies.PolicyConnectionString == "" {
		globalConf.Policies.PolicyConnectionString = hostname
		setHostname = true
	}

	if setHostname {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Info("Hostname set with dashboard zeroconf signal")
	}
}
