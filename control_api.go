package main

import (
	"fmt"
	"net/http"
	pprof_http "net/http/pprof"

	"github.com/lonelycode/osin"

	"github.com/TykTechnologies/tyk/cli"
	"github.com/TykTechnologies/tyk/config"

	"github.com/gorilla/mux"
)

// Set up default Tyk control API endpoints - these are global, so need to be added first
func loadAPIEndpoints(router *mux.Router) {
	hostname := config.Global().HostName
	if config.Global().ControlAPIHostname != "" {
		hostname = config.Global().ControlAPIHostname
	}

	if router == nil {
		router = defaultProxyMux.router(config.Global().ControlAPIPort, "")
		if router == nil {
			log.Error("Can't find control API router")
			return
		}
	}

	if hostname != "" {
		router = router.Host(hostname).Subrouter()
		mainLog.Info("Control API hostname set: ", hostname)
	}

	if *cli.HTTPProfile {
		router.HandleFunc("/debug/pprof/profile", pprof_http.Profile)
		router.HandleFunc("/debug/pprof/{_:.*}", pprof_http.Index)
	}

	router.HandleFunc("/"+config.Global().HealthCheckEndpointName, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello")
	})

	r := mux.NewRouter()
	r.MethodNotAllowedHandler = MethodNotAllowedHandler{}

	router.PathPrefix("/tyk/").Handler(http.StripPrefix("/tyk",
		stripSlashes(checkIsAPIOwner(controlAPICheckClientCertificate("/gateway/client", InstrumentationMW(r)))),
	))

	mainLog.Info("Initialising Tyk REST API Endpoints")

	// set up main API handlers
	r.HandleFunc("/reload/group", groupResetHandler).Methods("GET")
	r.HandleFunc("/reload", resetHandler(nil)).Methods("GET")

	if !isRPCMode() {
		r.HandleFunc("/org/keys", orgHandler).Methods("GET")
		r.HandleFunc("/org/keys/{keyName:[^/]*}", orgHandler).Methods("POST", "PUT", "GET", "DELETE")
		r.HandleFunc("/keys/policy/{keyName}", policyUpdateHandler).Methods("POST")
		r.HandleFunc("/keys/create", createKeyHandler).Methods("POST")
		r.HandleFunc("/apis", apiHandler).Methods("GET", "POST", "PUT", "DELETE")
		r.HandleFunc("/apis/{apiID}", apiHandler).Methods("GET", "POST", "PUT", "DELETE")
		r.HandleFunc("/health", healthCheckhandler).Methods("GET")
		r.HandleFunc("/oauth/clients/create", createOauthClient).Methods("POST")
		r.HandleFunc("/oauth/clients/{apiID}/{keyName:[^/]*}", oAuthClientHandler).Methods("PUT")
		r.HandleFunc("/oauth/refresh/{keyName}", invalidateOauthRefresh).Methods("DELETE")
		r.HandleFunc("/cache/{apiID}", invalidateCacheHandler).Methods("DELETE")
	} else {
		mainLog.Info("Node is slaved, REST API minimised")
	}

	r.HandleFunc("/debug", traceHandler).Methods("POST")

	r.HandleFunc("/keys", keyHandler).Methods("POST", "PUT", "GET", "DELETE")
	r.HandleFunc("/keys/{keyName:[^/]*}", keyHandler).Methods("POST", "PUT", "GET", "DELETE")
	r.HandleFunc("/certs", certHandler).Methods("POST", "GET")
	r.HandleFunc("/certs/{certID:[^/]*}", certHandler).Methods("POST", "GET", "DELETE")
	r.HandleFunc("/oauth/clients/{apiID}", oAuthClientHandler).Methods("GET", "DELETE")
	r.HandleFunc("/oauth/clients/{apiID}/{keyName:[^/]*}", oAuthClientHandler).Methods("GET", "DELETE")
	r.HandleFunc("/oauth/clients/{apiID}/{keyName}/tokens", oAuthClientTokensHandler).Methods("GET")

	mainLog.Debug("Loaded API Endpoints")
}

func controlAPICheckClientCertificate(certLevel string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.Global().Security.ControlAPIUseMutualTLS {
			if err := CertificateManager.ValidateRequestCertificate(config.Global().Security.Certificates.ControlAPI, r); err != nil {
				doJSONWrite(w, http.StatusForbidden, apiError(err.Error()))
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// checkIsAPIOwner will ensure that the accessor of the tyk API has the
// correct security credentials - this is a shared secret between the
// client and the owner and is set in the tyk.conf file. This should
// never be made public!
func checkIsAPIOwner(next http.Handler) http.Handler {
	secret := config.Global().Secret
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tykAuthKey := r.Header.Get("X-Tyk-Authorization")
		if tykAuthKey != secret {
			// Error
			mainLog.Warning("Attempted administrative access with invalid or missing key!")

			doJSONWrite(w, http.StatusForbidden, apiError("Forbidden"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func generateOAuthPrefix(apiID string) string {
	return "oauth-data." + apiID + "."
}

// Create API-specific OAuth handlers and respective auth servers
func addOAuthHandlers(spec *APISpec, muxer *mux.Router) *OAuthManager {
	apiAuthorizePath := spec.Proxy.ListenPath + "tyk/oauth/authorize-client{_:/?}"
	clientAuthPath := spec.Proxy.ListenPath + "oauth/authorize{_:/?}"
	clientAccessPath := spec.Proxy.ListenPath + "oauth/token{_:/?}"

	serverConfig := osin.NewServerConfig()
	serverConfig.ErrorStatusCode = http.StatusForbidden
	serverConfig.AllowedAccessTypes = spec.Oauth2Meta.AllowedAccessTypes
	serverConfig.AllowedAuthorizeTypes = spec.Oauth2Meta.AllowedAuthorizeTypes
	serverConfig.RedirectUriSeparator = config.Global().OauthRedirectUriSeparator

	prefix := generateOAuthPrefix(spec.APIID)
	storageManager := getGlobalStorageHandler(prefix, false)
	storageManager.Connect()
	osinStorage := &RedisOsinStorageInterface{storageManager, spec.SessionManager} //TODO: Needs storage manager from APISpec

	osinServer := TykOsinNewServer(serverConfig, osinStorage)

	oauthManager := OAuthManager{spec, osinServer}
	oauthHandlers := OAuthHandlers{oauthManager}

	muxer.Handle(apiAuthorizePath, checkIsAPIOwner(allowMethods(oauthHandlers.HandleGenerateAuthCodeData, "POST")))
	muxer.HandleFunc(clientAuthPath, allowMethods(oauthHandlers.HandleAuthorizePassthrough, "GET", "POST"))
	muxer.HandleFunc(clientAccessPath, allowMethods(oauthHandlers.HandleAccessRequest, "GET", "POST"))

	return &oauthManager
}

func addBatchEndpoint(spec *APISpec, muxer *mux.Router) {
	mainLog.Debug("Batch requests enabled for API")
	apiBatchPath := spec.Proxy.ListenPath + "tyk/batch/"
	batchHandler := BatchRequestHandler{API: spec}
	muxer.HandleFunc(apiBatchPath, batchHandler.HandleBatchRequest)
}
