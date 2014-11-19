package main

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
)

// Config is the configuration object used by tyk to set up various parameters.
type Config struct {
	ListenPort      int    `json:"listen_port"`
	Secret          string `json:"secret"`
	TemplatePath    string `json:"template_path"`
	UseDBAppConfigs bool   `json:"use_db_app_configs"`
	AppPath         string `json:"app_path"`
	Storage         struct {
		Type     string `json:"type"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
		Database int    `json:"database"`
	} `json:"storage"`
	EnableAnalytics bool `json:"enable_analytics"`
	AnalyticsConfig struct {
		Type            string `json:"type"`
		CSVDir          string `json:"csv_dir"`
		MongoURL        string `json:"mongo_url"`
		MongoDbName     string `json:"mongo_db_name"`
		MongoCollection string `json:"mongo_collection"`
		PurgeDelay      int    `json:"purge_delay"`
		IgnoredIPs      []string `json:"ignored_ips"`
		ignoredIPsCompiled map[string]bool
	} `json:"analytics_config"`
}

// WriteDefaultConf will create a default configuration file and set the storage type to "memory"
func WriteDefaultConf(configStruct *Config) {
	configStruct.ListenPort = 8080
	configStruct.Secret = "352d20ee67be67f6340b4c0605b044b7"
	configStruct.TemplatePath = "./templates"
	configStruct.Storage.Type = "redis"
	configStruct.AppPath = "./apps/"
	configStruct.Storage.Host = "localhost"
	configStruct.Storage.Username = ""
	configStruct.Storage.Password = ""
	configStruct.Storage.Database = 0
	configStruct.Storage.Port = 6379
	configStruct.EnableAnalytics = false
	configStruct.AnalyticsConfig.CSVDir = "/tmp"
	configStruct.AnalyticsConfig.Type = "csv"
	configStruct.AnalyticsConfig.IgnoredIPs = make([]string, 0)
	newConfig, err := json.Marshal(configStruct)
	if err != nil {
		log.Error("Problem marshalling default configuration!")
		log.Error(err)
	} else {
		ioutil.WriteFile("tyk.conf", newConfig, 0644)
	}
}

// LoadConfig will load the configuration file from filePath, if it can't open
// the file for reading, it assumes there is no configuration file and will try to create
// one on the default path (tyk.conf in the local directory)
func loadConfig(filePath string, configStruct *Config) {
	configuration, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Error("Couldn't load configuration file")
		log.Error(err)
		log.Info("Writing a default file to ./tyk.conf")

		WriteDefaultConf(configStruct)

		log.Info("Loading default configuration...")
		loadConfig("tyk.conf", configStruct)
	} else {
		err := json.Unmarshal(configuration, &configStruct)
		if err != nil {
			log.Error("Couldn't unmarshal configuration")
			log.Error(err)
		}
	}
}

func (c *Config) loadIgnoredIPs() {
	c.AnalyticsConfig.ignoredIPsCompiled = make(map[string]bool, len(c.AnalyticsConfig.IgnoredIPs))
	for _, ip := range c.AnalyticsConfig.IgnoredIPs {
		c.AnalyticsConfig.ignoredIPsCompiled[ip] = true;
	}
}

func (c *Config) TestShowIPs() {
	log.Warning(c.AnalyticsConfig.ignoredIPsCompiled)
}

func (c Config) StoreAnalytics(r *http.Request) (bool) {
	if !c.EnableAnalytics {
		return false;
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)

	forwarded := r.Header.Get("X-FORWARDED-FOR")
	if forwarded != "" {
		ips := strings.Split(forwarded, ", ")
		ip = ips[0]
	}

	_, ignore := c.AnalyticsConfig.ignoredIPsCompiled[ip]

	return !ignore
}
