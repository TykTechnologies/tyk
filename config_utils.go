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
func WriteDefaultConf(conf *Config) {
	conf.ListenAddress = ""
	conf.ListenPort = 8080
	conf.Secret = "352d20ee67be67f6340b4c0605b044b7"
	conf.TemplatePath = "./templates"
	conf.TykJSPath = "./js/tyk.js"
	conf.MiddlewarePath = "./middleware"
	conf.Storage.Type = "redis"
	conf.AppPath = "./apps/"
	conf.Storage.Host = "localhost"
	conf.Storage.Username = ""
	conf.Storage.Password = ""
	conf.Storage.Database = 0
	conf.Storage.MaxIdle = 100
	conf.Storage.Port = 6379
	conf.EnableAnalytics = false
	conf.HealthCheck.EnableHealthChecks = true
	conf.HealthCheck.HealthCheckValueTimeout = 60
	conf.AnalyticsConfig.IgnoredIPs = make([]string, 0)
	conf.UseAsyncSessionWrite = false
	conf.HideGeneratorHeader = false
	conf.OauthRedirectUriSeparator = ""
	newConfig, err := json.MarshalIndent(conf, "", "    ")
	overrideErr := envconfig.Process(ENV_PREVIX, conf)
	if overrideErr != nil {
		log.Error("Failed to process environment variables: ", overrideErr)
	}
	if err != nil {
		log.Error("Problem marshalling default configuration!")
		log.Error(err)
	} else if !runningTests {
		ioutil.WriteFile("tyk.conf", newConfig, 0644)
	}
}

// LoadConfig will load the configuration file from filePath, if it can't open
// the file for reading, it assumes there is no configuration file and will try to create
// one on the default path (tyk.conf in the local directory)
func loadConfig(filePath string, conf *Config) {
	configuration, err := ioutil.ReadFile(filePath)
	if err != nil {
		if !runningTests {
			log.Error("Couldn't load configuration file")
			log.Error(err)
			log.Info("Writing a default file to ./tyk.conf")
			WriteDefaultConf(conf)
			log.Info("Loading default configuration...")
			loadConfig("tyk.conf", conf)
		}
	} else {
		if err := json.Unmarshal(configuration, &conf); err != nil {
			log.Error("Couldn't unmarshal configuration")
			log.Error(err)
		}

		overrideErr := envconfig.Process(ENV_PREVIX, conf)
		if overrideErr != nil {
			log.Error("Failed to process environment variables after file load: ", overrideErr)
		}
	}

	if conf.SlaveOptions.CallTimeout == 0 {
		conf.SlaveOptions.CallTimeout = 30
	}
	if conf.SlaveOptions.PingTimeout == 0 {
		conf.SlaveOptions.PingTimeout = 60
	}
	GlobalRPCPingTimeout = time.Second * time.Duration(conf.SlaveOptions.PingTimeout)
	GlobalRPCCallTimeout = time.Second * time.Duration(conf.SlaveOptions.CallTimeout)
	conf.EventTriggers = InitGenericEventHandlers(conf.EventHandlers)
}

func (c *Config) loadIgnoredIPs() {
	c.AnalyticsConfig.ignoredIPsCompiled = make(map[string]bool, len(c.AnalyticsConfig.IgnoredIPs))
	for _, ip := range c.AnalyticsConfig.IgnoredIPs {
		c.AnalyticsConfig.ignoredIPsCompiled[ip] = true
	}
}

func (c *Config) StoreAnalytics(r *http.Request) bool {
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
