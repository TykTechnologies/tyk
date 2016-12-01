package main

import (
	"encoding/json"
	"github.com/TykTechnologies/logrus"
	"strings"
	"strconv"
)

type DashboardConfigPayload struct {
	DashboardConfig struct {
		Hostname string
		Port     int
		UseTLS   bool
	}
	TimeStamp int64
}

func createConnectionStringFromDashboardObject(thisConfig DashboardConfigPayload) string {
	thisHostname := "http://"
	if thisConfig.DashboardConfig.UseTLS {
		thisHostname = "https://"
	}

	thisHostname = thisHostname + thisConfig.DashboardConfig.Hostname

	if thisConfig.DashboardConfig.Port != 0 {
		strings.TrimRight(thisHostname, "/")
		thisHostname = thisHostname + ":" + strconv.Itoa(thisConfig.DashboardConfig.Port)
	}

	return thisHostname
}

func HandleDashboardZeroConfMessage(payload string) {
	// Decode the configuration from the payload
	thisDashboardPayload := DashboardConfigPayload{}
	err := json.Unmarshal([]byte(payload), &thisDashboardPayload)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to decode dashboard zeroconf payload")
		return
	}

	if !config.UseDBAppConfigs {
		return
	}

	if config.DisableDashboardZeroConf {
		return
	}

	thisHostname := createConnectionStringFromDashboardObject(thisDashboardPayload)
	setHostname := false
	if config.DBAppConfOptions.ConnectionString == "" {
		config.DBAppConfOptions.ConnectionString = thisHostname
		setHostname = true
	}

	if config.Policies.PolicyConnectionString == "" {
		config.Policies.PolicyConnectionString = thisHostname
		setHostname = true
	}

	if setHostname {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Info("Hostname set with dashboard zeroconf signal")
	}
}
