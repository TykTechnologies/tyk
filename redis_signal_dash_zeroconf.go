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

	if !config.UseDBAppConfigs {
		return
	}

	if config.DisableDashboardZeroConf {
		return
	}

	hostname := createConnectionStringFromDashboardObject(dashPayload)
	setHostname := false
	if config.DBAppConfOptions.ConnectionString == "" {
		config.DBAppConfOptions.ConnectionString = hostname
		setHostname = true
	}

	if config.Policies.PolicyConnectionString == "" {
		config.Policies.PolicyConnectionString = hostname
		setHostname = true
	}

	if setHostname {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Info("Hostname set with dashboard zeroconf signal")
	}
}
