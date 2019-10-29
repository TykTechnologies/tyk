package gateway

import (
	"crypto/tls"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/certs"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/dashboard"
)

var (
	dashLog          = log.WithField("prefix", "dashboard")
	dashboardTimeout = 5 * time.Second

	// Nonce to use when interacting with the dashboard service
	ServiceNonce string
	nonceMutex   sync.RWMutex
)

type DashboardServiceSender interface {
	Register() error
	DeRegister() error
	StartBeating()
	StopBeating()
	NotifyDashboardOfEvent(interface{}) error
	FetchApiSpecs(nonce string) (*dashboard.TaggedApis, error)
}

func UpdateNonce(nonce string) {
	nonceMutex.Lock()
	defer nonceMutex.Unlock()

	ServiceNonce = nonce
}

func GetNonce() string {
	nonceMutex.RLock()
	defer nonceMutex.RUnlock()

	return ServiceNonce
}

func dashboardServiceInit() {
	secret := config.Global().NodeSecret
	if secret == "" {
		dashLog.Fatal("Node secret is not set, required for dashboard connection")
	}

	if DashService == nil {
		DashService = dashboard.NewHandler(
			DashboardHttpClient(dashboardTimeout),
			log.WithField("prefix", "dashboard"),
			hostDetails.Hostname,
			GetNodeID(),
			secret,
			DashboardConnectionString(),
			GetNonce,
			UpdateNonce,
			SetNodeID,
		)
	}
}

func handleDashboardRegistration() {
	if !config.Global().UseDBAppConfigs {
		return
	}

	dashboardServiceInit()

	if err := DashService.Register(); err != nil {
		dashLog.Fatal("Registration failed: ", err)
	}

	go DashService.StartBeating()
}

func reLogin() {
	if !config.Global().UseDBAppConfigs {
		return
	}

	dashLog.Info("Registering node (again).")
	DashService.StopBeating()
	if err := DashService.DeRegister(); err != nil {
		dashLog.Error("Could not deregister: ", err)
	}

	time.Sleep(5 * time.Second)

	if err := DashService.Register(); err != nil {
		dashLog.Error("Could not register: ", err)
	} else {
		go DashService.StartBeating()
	}

	dashLog.Info("Recovering configurations, reloading...")
	reloadURLStructure(nil)
}

func DashboardConnectionString() string {
	if config.Global().DBAppConfOptions.ConnectionString == "" && config.Global().DisableDashboardZeroConf {
		dashLog.Fatal("Connection string is empty, failing.")
	}

	if !config.Global().DisableDashboardZeroConf && config.Global().DBAppConfOptions.ConnectionString == "" {
		dashLog.Info("Waiting for zeroconf signal...")
		for config.Global().DBAppConfOptions.ConnectionString == "" {
			time.Sleep(1 * time.Second)
		}
	}

	return config.Global().DBAppConfOptions.ConnectionString
}

func DashboardHttpClient(timeout time.Duration) (client *http.Client) {
	client = &http.Client{Timeout: timeout}

	cfg := config.Global()
	if !cfg.HttpServerOptions.UseSSL && !strings.HasPrefix(cfg.DBAppConfOptions.ConnectionString, "https") {
		return
	}

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.HttpServerOptions.SSLInsecureSkipVerify,
	}

	cert := cfg.Security.Certificates.Dashboard
	if strings.TrimSpace(cert) != "" {
		certsList := CertificateManager.List([]string{cert}, certs.CertificatePrivate)

		if len(certsList) != 0 && certsList[0] != nil {
			tlsConfig.Certificates = []tls.Certificate{*certsList[0]}
			dashLog.Info("Mutual tls for dashboard was enabled")
		} else {
			dashLog.Infof("No dashboard certificate with id: %v was found", cert)
		}
	}

	client.Transport = &http.Transport{TLSClientConfig: tlsConfig}

	return
}
