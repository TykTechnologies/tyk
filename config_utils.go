package main

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/nu7hatch/gouuid"
)

const ENV_PREVIX = "TYK_GW"

// WriteDefaultConf will create a default configuration file and set the storage type to "memory"
func WriteDefaultConf(configStruct *Config) {
	configStruct.ListenAddress = ""
	configStruct.ListenPort = 8080
	configStruct.Secret = "352d20ee67be67f6340b4c0605b044b7"
	configStruct.TemplatePath = "./templates"
	configStruct.TykJSPath = "./js/tyk.js"
	configStruct.MiddlewarePath = "./middleware"
	configStruct.Storage.Type = "redis"
	configStruct.AppPath = "./apps/"
	configStruct.Storage.Host = "localhost"
	configStruct.Storage.Username = ""
	configStruct.Storage.Password = ""
	configStruct.Storage.Database = 0
	configStruct.Storage.MaxIdle = 100
	configStruct.Storage.Port = 6379
	configStruct.EnableAnalytics = false
	configStruct.HealthCheck.EnableHealthChecks = true
	configStruct.HealthCheck.HealthCheckValueTimeout = 60
	configStruct.AnalyticsConfig.IgnoredIPs = make([]string, 0)
	configStruct.UseAsyncSessionWrite = false
	configStruct.HideGeneratorHeader = false
	configStruct.OauthRedirectUriSeparator = ""
	newConfig, err := json.MarshalIndent(configStruct, "", "    ")
	overrideErr := envconfig.Process(ENV_PREVIX, &configStruct)
	if overrideErr != nil {
		log.Error("Failed to process environment variables: ", overrideErr)
	}
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

		overrideErr := envconfig.Process(ENV_PREVIX, configStruct)
		if overrideErr != nil {
			log.Error("Failed to process environment variables after file load: ", overrideErr)
		}
	}

	if configStruct.SlaveOptions.CallTimeout == 0 {
		configStruct.SlaveOptions.CallTimeout = 30
	}
	if configStruct.SlaveOptions.PingTimeout == 0 {
		configStruct.SlaveOptions.PingTimeout = 60
	}
	GlobalRPCPingTimeout = time.Second * time.Duration(configStruct.SlaveOptions.PingTimeout)
	GlobalRPCCallTimeout = time.Second * time.Duration(configStruct.SlaveOptions.CallTimeout)
	configStruct.EventTriggers = InitGenericEventHandlers(configStruct.EventHandlers)
}

func (c *Config) loadIgnoredIPs() {
	c.AnalyticsConfig.ignoredIPsCompiled = make(map[string]bool, len(c.AnalyticsConfig.IgnoredIPs))
	for _, ip := range c.AnalyticsConfig.IgnoredIPs {
		c.AnalyticsConfig.ignoredIPsCompiled[ip] = true
	}
}

func (c Config) StoreAnalytics(r *http.Request) bool {
	if !c.EnableAnalytics {
		return false
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

func generateRandomNodeID() string {
	u, _ := uuid.NewV4()
	return "solo-" + u.String()
}
