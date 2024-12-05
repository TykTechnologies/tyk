package gateway

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gocraft/health"
	"github.com/justinas/alice"
	newrelic "github.com/newrelic/go-agent"
	"github.com/paulbellamy/ratecounter"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/TykTechnologies/tyk/internal/event"
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/internal/policy"
	"github.com/TykTechnologies/tyk/request"
	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/trace"
	"github.com/TykTechnologies/tyk/user"
)

const (
	mwStatusRespond                = middleware.StatusRespond
	DEFAULT_ORG_SESSION_EXPIRATION = int64(604800)
)

var (
	GlobalRate            = ratecounter.NewRateCounter(1 * time.Second)
	orgSessionExpiryCache singleflight.Group
)

type TykMiddleware interface {
	Base() *BaseMiddleware
	GetSpec() *APISpec

	Init()
	SetName(string)
	Logger() *logrus.Entry
	Config() (interface{}, error)
	ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) // Handles request
	EnabledForSpec() bool
	Name() string

	Unload()
}

type TraceMiddleware struct {
	TykMiddleware
}

func (tr TraceMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) {
	if trace.IsEnabled() {
		span, ctx := trace.Span(r.Context(),
			tr.Name(),
		)
		defer span.Finish()
		setContext(r, ctx)
		return tr.TykMiddleware.ProcessRequest(w, r, conf)
	} else if baseMw := tr.Base(); baseMw != nil {
		cfg := baseMw.Gw.GetConfig()
		if cfg.OpenTelemetry.Enabled {
			otel.AddTraceID(r.Context(), w)
			var span otel.Span
			if baseMw.Spec.DetailedTracing {
				var ctx context.Context
				ctx, span = baseMw.Gw.TracerProvider.Tracer().Start(r.Context(), tr.Name())
				defer span.End()
				setContext(r, ctx)
			} else {
				span = otel.SpanFromContext(r.Context())
			}

			err, i := tr.TykMiddleware.ProcessRequest(w, r, conf)
			if err != nil {
				span.SetStatus(otel.SPAN_STATUS_ERROR, err.Error())
			}

			attrs := ctxGetSpanAttributes(r, tr.TykMiddleware.Name())
			if len(attrs) > 0 {
				span.SetAttributes(attrs...)
			}

			return err, i
		}
	}

	return tr.TykMiddleware.ProcessRequest(w, r, conf)
}

func (gw *Gateway) createDynamicMiddleware(name string, isPre, useSession bool, baseMid *BaseMiddleware) func(http.Handler) http.Handler {
	dMiddleware := &DynamicMiddleware{
		BaseMiddleware:      baseMid,
		MiddlewareClassName: name,
		Pre:                 isPre,
		UseSession:          useSession,
	}

	return gw.createMiddleware(dMiddleware)
}

// Generic middleware caller to make extension easier
func (gw *Gateway) createMiddleware(actualMW TykMiddleware) func(http.Handler) http.Handler {
	mw := &TraceMiddleware{
		TykMiddleware: actualMW,
	}
	// construct a new instance
	mw.Init()
	mw.SetName(mw.Name())
	mw.Logger().Debug("Init")

	spec := mw.GetSpec()
	spec.AddUnloadHook(actualMW.Unload)

	// Pull the configuration
	mwConf, err := mw.Config()
	if err != nil {
		mw.Logger().Fatal("[Middleware] Configuration load failed")
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := mw.Base().SetRequestLogger(r)

			if gw.GetConfig().NewRelic.AppName != "" {
				if txn, ok := w.(newrelic.Transaction); ok {
					defer newrelic.StartSegment(txn, mw.Name()).End()
				}
			}

			job := instrument.NewJob("MiddlewareCall")
			meta := health.Kvs{}
			eventName := mw.Name() + "." + "executed"

			if instrumentationEnabled {
				meta = health.Kvs{
					"from_ip":  request.RealIP(r),
					"method":   r.Method,
					"endpoint": r.URL.Path,
					"raw_url":  r.URL.String(),
					"size":     strconv.Itoa(int(r.ContentLength)),
					"mw_name":  mw.Name(),
				}
				job.EventKv("executed", meta)
				job.EventKv(eventName, meta)
			}

			startTime := time.Now()
			logger.WithField("ts", startTime.UnixNano()).WithField("mw", mw.Name()).Debug("Started")

			if mw.Base().Spec.CORS.OptionsPassthrough && r.Method == "OPTIONS" {
				h.ServeHTTP(w, r)
				return
			}

			err, errCode := mw.ProcessRequest(w, r, mwConf)

			if err != nil {
				writeResponse := true
				// Prevent double error write
				if goPlugin, isGoPlugin := actualMW.(*GoPluginMiddleware); isGoPlugin && goPlugin.handler != nil {
					writeResponse = false
				}

				handler := ErrorHandler{mw.Base()}
				handler.HandleError(w, r, err.Error(), errCode, writeResponse)

				meta["error"] = err.Error()

				finishTime := time.Since(startTime)

				if instrumentationEnabled {
					job.TimingKv("exec_time", finishTime.Nanoseconds(), meta)
					job.TimingKv(eventName+".exec_time", finishTime.Nanoseconds(), meta)
				}

				logger.WithError(err).WithField("code", errCode).WithField("ns", finishTime.Nanoseconds()).Debug("Finished")
				return
			}

			finishTime := time.Since(startTime)

			if instrumentationEnabled {
				job.TimingKv("exec_time", finishTime.Nanoseconds(), meta)
				job.TimingKv(eventName+".exec_time", finishTime.Nanoseconds(), meta)
			}

			logger.WithField("code", errCode).WithField("ns", finishTime.Nanoseconds()).Debug("Finished")

			mw.Base().UpdateRequestSession(r)
			// Special code, bypasses all other execution
			if errCode != mwStatusRespond {
				// No error, carry on...
				meta["bypass"] = "1"
				h.ServeHTTP(w, r)
			}
		})
	}
}

func (gw *Gateway) mwAppendEnabled(chain *[]alice.Constructor, mw TykMiddleware) bool {
	if mw.EnabledForSpec() {
		*chain = append(*chain, gw.createMiddleware(mw))
		return true
	}
	return false
}

func (gw *Gateway) responseMWAppendEnabled(chain *[]TykResponseHandler, responseMW TykResponseHandler) bool {
	if responseMW.Enabled() {
		*chain = append(*chain, responseMW)
		return true
	}

	return false
}

func (gw *Gateway) mwList(mws ...TykMiddleware) []alice.Constructor {
	var list []alice.Constructor
	for _, mw := range mws {
		gw.mwAppendEnabled(&list, mw)
	}
	return list
}

// BaseMiddleware wraps up the ApiSpec and Proxy objects to be included in a
// middleware handler, this can probably be handled better.
type BaseMiddleware struct {
	Spec  *APISpec
	Proxy ReturningHttpHandler
	Gw    *Gateway `json:"-"`

	loggerMu sync.RWMutex
	logger   *logrus.Entry
}

// NewBaseMiddleware creates a new *BaseMiddleware.
// The passed logrus.Entry is duplicated.
// BaseMiddleware keeps the pointer to *Gateway and *APISpec, as well as Proxy.
// The logger duplication is used so that basemiddleware copies can be created for different middleware.
func NewBaseMiddleware(gw *Gateway, spec *APISpec, proxy ReturningHttpHandler, logger *logrus.Entry) *BaseMiddleware {
	if logger == nil {
		logger = logrus.NewEntry(log)
	}
	baseMid := &BaseMiddleware{
		Spec:   spec,
		Proxy:  proxy,
		logger: logger.Dup(),
		Gw:     gw,
	}

	for _, v := range baseMid.Spec.VersionData.Versions {
		if len(v.ExtendedPaths.CircuitBreaker) > 0 {
			baseMid.Spec.CircuitBreakerEnabled = true
		}
		if len(v.ExtendedPaths.HardTimeouts) > 0 {
			baseMid.Spec.EnforcedTimeoutEnabled = true
		}
	}

	return baseMid
}

// Copy provides a new BaseMiddleware with it's own logger scope (copy).
// The Spec, Proxy and Gw values are not copied.
func (m *BaseMiddleware) Copy() *BaseMiddleware {
	return &BaseMiddleware{
		logger: m.logger.Dup(),
		Spec:   m.Spec,
		Proxy:  m.Proxy,
		Gw:     m.Gw,
	}
}

// Base serves to provide the full BaseMiddleware API. It's part of the TykMiddleware interface.
// It escapes to a wider API surface than TykMiddleware, used by middlewares, etc.
func (t *BaseMiddleware) Base() *BaseMiddleware {
	return t
}

func (t *BaseMiddleware) SetName(name string) {
	t.logger = t.logger.WithField("mw", name)
}

// Logger is used by middleware process functions.
func (t *BaseMiddleware) Logger() (logger *logrus.Entry) {
	t.loggerMu.RLock()
	defer t.loggerMu.RUnlock()

	return t.logger
}

func (t *BaseMiddleware) SetRequestLogger(r *http.Request) *logrus.Entry {
	t.loggerMu.Lock()
	defer t.loggerMu.Unlock()

	t.logger = t.Gw.getLogEntryForRequest(t.Logger(), r, ctxGetAuthToken(r), nil)
	return t.logger
}

func (t *BaseMiddleware) Init() {}
func (t *BaseMiddleware) EnabledForSpec() bool {
	return true
}
func (t *BaseMiddleware) Config() (interface{}, error) {
	return nil, nil
}

// Unload unloads the middleware and frees resources
func (t *BaseMiddleware) Unload() {
	// methos created to satisfy middleware contract
}

// GetSpec returns the spec of the middleware
func (t *BaseMiddleware) GetSpec() *APISpec {
	return t.Spec
}

func (t *BaseMiddleware) OrgSession(orgID string) (user.SessionState, bool) {

	if rpc.IsEmergencyMode() {
		return user.SessionState{}, false
	}

	// Try and get the session from the session store
	session, found := t.Spec.OrgSessionManager.SessionDetail(orgID, orgID, false)
	if found && t.Spec.GlobalConfig.EnforceOrgDataAge {
		// If exists, assume it has been authorized and pass on
		// We cache org expiry data
		t.Logger().Debug("Setting data expiry: ", orgID)

		t.Gw.ExpiryCache.Set(session.OrgID, session.DataExpires, cache.DefaultExpiration)
	}

	session.SetKeyHash(storage.HashKey(orgID, t.Gw.GetConfig().HashKeys))

	return session.Clone(), found
}

func (t *BaseMiddleware) SetOrgExpiry(orgid string, expiry int64) {
	t.Gw.ExpiryCache.Set(orgid, expiry, cache.DefaultExpiration)
}

func (t *BaseMiddleware) OrgSessionExpiry(orgid string) int64 {
	t.Logger().Debug("Checking: ", orgid)

	// Cache failed attempt
	id, err, _ := orgSessionExpiryCache.Do(orgid, func() (interface{}, error) {
		cachedVal, found := t.Gw.ExpiryCache.Get(orgid)
		if found {
			return cachedVal, nil
		}

		s, found := t.OrgSession(orgid)
		if found && t.Spec.GlobalConfig.EnforceOrgDataAge {
			return s.DataExpires, nil
		}
		return 0, errors.New("missing session")
	})

	if err != nil {
		t.Logger().Debug("no cached entry found, returning 7 days")
		t.SetOrgExpiry(orgid, DEFAULT_ORG_SESSION_EXPIRATION)
		return DEFAULT_ORG_SESSION_EXPIRATION
	}

	return id.(int64)
}

func (t *BaseMiddleware) UpdateRequestSession(r *http.Request) bool {
	session := ctxGetSession(r)
	token := ctxGetAuthToken(r)

	if session == nil || token == "" {
		return false
	}

	if !session.IsModified() {
		return false
	}

	lifetime := session.Lifetime(t.Spec.GetSessionLifetimeRespectsKeyExpiration(), t.Spec.SessionLifetime, t.Gw.GetConfig().ForceGlobalSessionLifetime, t.Gw.GetConfig().GlobalSessionLifetime)
	if err := t.Gw.GlobalSessionManager.UpdateSession(token, session, lifetime, false); err != nil {
		t.Logger().WithError(err).Error("Can't update session")
		return false
	}

	// Reset session state, useful for benchmarks when request object stays the same.
	session.Reset()

	if !t.Spec.GlobalConfig.LocalSessionCache.DisableCacheSessionState {
		t.Gw.SessionCache.Set(session.KeyHash(), session.Clone(), cache.DefaultExpiration)
	}

	return true
}

// ApplyPolicies will check if any policies are loaded. If any are, it
// will overwrite the session state to use the policy values.
func (t *BaseMiddleware) ApplyPolicies(session *user.SessionState) error {
	var orgID *string
	if t.Spec != nil {
		orgID = &t.Spec.OrgID
	}
	store := policy.New(orgID, t.Gw, log)
	return store.Apply(session)
}

func copyAllowedURLs(input []user.AccessSpec) []user.AccessSpec {
	if input == nil {
		return nil
	}

	copied := make([]user.AccessSpec, len(input))

	for i, as := range input {
		copied[i] = user.AccessSpec{
			URL: as.URL,
		}
		if as.Methods != nil {
			copied[i].Methods = make([]string, len(as.Methods))
			copy(copied[i].Methods, as.Methods)
		}
	}

	return copied
}

// CheckSessionAndIdentityForValidKey will check first the Session store for a valid key, if not found, it will try
// the Auth Handler, if not found it will fail
func (t *BaseMiddleware) CheckSessionAndIdentityForValidKey(originalKey string, r *http.Request) (user.SessionState, bool) {
	key := originalKey
	minLength := t.Spec.GlobalConfig.MinTokenLength
	if minLength == 0 {
		// See https://github.com/TykTechnologies/tyk/issues/1681
		minLength = 3
	}

	if len(key) <= minLength {
		return user.SessionState{IsInactive: true}, false
	}

	// Try and get the session from the session store
	t.Logger().Debug("Querying local cache")
	keyHash := key
	cacheKey := key
	if t.Spec.GlobalConfig.HashKeys {
		cacheKey = storage.HashStr(key, storage.HashMurmur64) // always hash cache keys with murmur64 to prevent collisions
	}

	// Check in-memory cache
	if !t.Spec.GlobalConfig.LocalSessionCache.DisableCacheSessionState {
		cachedVal, found := t.Gw.SessionCache.Get(cacheKey)
		if found {
			t.Logger().Debug("--> Key found in local cache")
			session := cachedVal.(user.SessionState).Clone()
			if err := t.ApplyPolicies(&session); err != nil {
				t.Logger().Error(err)
				return session, false
			}
			return session, true
		}
	}

	// Check session store
	t.Logger().Debug("Querying keystore")
	session, found := t.Gw.GlobalSessionManager.SessionDetail(t.Spec.OrgID, key, false)

	if found {
		if t.Spec.GlobalConfig.HashKeys {
			keyHash = storage.HashStr(session.KeyID)
		}
		session := session.Clone()
		session.SetKeyHash(keyHash)
		// If exists, assume it has been authorized and pass on
		// cache it
		if !t.Spec.GlobalConfig.LocalSessionCache.DisableCacheSessionState {
			t.Gw.SessionCache.Set(cacheKey, session, cache.DefaultExpiration)
		}

		// Check for a policy, if there is a policy, pull it and overwrite the session values
		if err := t.ApplyPolicies(&session); err != nil {
			t.Logger().Error(err)
			return session, false
		}
		t.Logger().Debug("Got key")
		return session, true
	}

	if _, ok := t.Spec.AuthManager.Store().(*RPCStorageHandler); ok && rpc.IsEmergencyMode() {
		return session.Clone(), false
	}

	// Only search in RPC if it's not in emergency mode
	t.Logger().Debug("Querying authstore")
	// 2. If not there, get it from the AuthorizationHandler
	session, found = t.Spec.AuthManager.SessionDetail(t.Spec.OrgID, key, false)
	if found {
		key = session.KeyID

		session := session.Clone()
		session.SetKeyHash(keyHash)
		// If not in Session, and got it from AuthHandler, create a session with a new TTL
		t.Logger().Info("Recreating session for key: ", t.Gw.obfuscateKey(key))

		// cache it
		if !t.Spec.GlobalConfig.LocalSessionCache.DisableCacheSessionState {
			go t.Gw.SessionCache.Set(cacheKey, session, cache.DefaultExpiration)
		}

		// Check for a policy, if there is a policy, pull it and overwrite the session values
		if err := t.ApplyPolicies(&session); err != nil {
			t.Logger().Error(err)
			return session, false
		}

		t.Logger().Debug("Lifetime is: ", session.Lifetime(t.Spec.GetSessionLifetimeRespectsKeyExpiration(), t.Spec.SessionLifetime, t.Gw.GetConfig().ForceGlobalSessionLifetime, t.Gw.GetConfig().GlobalSessionLifetime))

		session.Touch()

		return session, found
	}

	// session not found
	session.KeyID = key
	return session, false
}

// FireEvent is added to the BaseMiddleware object so it is available across the entire stack
func (t *BaseMiddleware) FireEvent(name apidef.TykEvent, meta interface{}) {
	fireEvent(name, meta, t.Spec.EventPaths)
}

// emitRateLimitEvents emits rate limit related events based on the request context.
func (t *BaseMiddleware) emitRateLimitEvents(r *http.Request, rateLimitKey string) {
	// Emit events triggered from request context.
	if events := event.Get(r.Context()); len(events) > 0 {
		for _, e := range events {
			switch e {
			case event.RateLimitSmoothingUp, event.RateLimitSmoothingDown:
				t.emitRateLimitEvent(r, e, "", rateLimitKey)
			}
		}
	}
}

// emitRateLimitEvent emits a specific rate limit event with an optional custom message.
func (t *BaseMiddleware) emitRateLimitEvent(r *http.Request, e event.Event, message string, rateLimitKey string) {
	if message == "" {
		message = event.String(e)
	}

	t.Logger().WithField("key", t.Gw.obfuscateKey(rateLimitKey)).Info(message)

	t.FireEvent(e, EventKeyFailureMeta{
		EventMetaDefault: EventMetaDefault{
			Message:            message,
			OriginatingRequest: EncodeRequestToEvent(r),
		},
		Path:   r.URL.Path,
		Origin: request.RealIP(r),
		Key:    rateLimitKey,
	})
}

// handleRateLimitFailure handles the actions to be taken when a rate limit failure occurs.
func (t *BaseMiddleware) handleRateLimitFailure(r *http.Request, e event.Event, message string, rateLimitKey string) (error, int) {
	t.emitRateLimitEvent(r, e, message, rateLimitKey)

	// Report in health check
	reportHealthValue(t.Spec, Throttle, "-1")

	return errors.New(message), http.StatusTooManyRequests
}

func (t *BaseMiddleware) getAuthType() string {
	return ""
}

func (t *BaseMiddleware) getAuthToken(authType string, r *http.Request) (string, apidef.AuthConfig) {
	spec := t.Base().Spec
	config, ok := spec.AuthConfigs[authType]
	// Auth is deprecated. To maintain backward compatibility authToken and jwt cases are added.
	if !ok && (authType == apidef.AuthTokenType || authType == apidef.JWTType) {
		config = spec.Auth
	}

	var (
		key         string
		defaultName = header.Authorization
	)

	headerName := config.AuthHeaderName
	if !config.DisableHeader {
		if headerName == "" {
			headerName = defaultName
		} else {
			defaultName = headerName
		}

		key = r.Header.Get(headerName)
	}

	paramName := config.ParamName
	if config.UseParam {
		if paramName == "" {
			paramName = defaultName
		}

		paramValue := r.URL.Query().Get(paramName)

		// Only use the paramValue if it has an actual value
		if paramValue != "" {
			key = paramValue
		}
	}

	cookieName := config.CookieName
	if config.UseCookie {
		if cookieName == "" {
			cookieName = defaultName
		}

		authCookie, err := r.Cookie(cookieName)
		cookieValue := ""
		if err == nil {
			cookieValue = authCookie.Value
		}

		if cookieValue != "" {
			key = cookieValue
		}
	}

	return key, config
}

func (t *BaseMiddleware) generateSessionID(id string) string {
	// generate a virtual token
	data := []byte(id)
	keyID := fmt.Sprintf("%x", md5.Sum(data))
	return t.Gw.generateToken(t.Spec.OrgID, keyID)
}

type TykResponseHandler interface {
	Enabled() bool
	Init(interface{}, *APISpec) error
	Name() string
	HandleResponse(http.ResponseWriter, *http.Response, *http.Request, *user.SessionState) error
	HandleError(http.ResponseWriter, *http.Request)
	Base() *BaseTykResponseHandler
}

type TykGoPluginResponseHandler interface {
	TykResponseHandler
	HandleGoPluginResponse(http.ResponseWriter, *http.Response, *http.Request) error
}

func (gw *Gateway) responseProcessorByName(name string, baseHandler BaseTykResponseHandler) TykResponseHandler {
	switch name {
	case "response_body_transform_jq":
		return &ResponseTransformJQMiddleware{BaseTykResponseHandler: baseHandler}
	case "header_transform":
		return &HeaderTransform{BaseTykResponseHandler: baseHandler}
	case "custom_mw_res_hook":
		return &CustomMiddlewareResponseHook{BaseTykResponseHandler: baseHandler}
	case "goplugin_res_hook":
		return &ResponseGoPluginMiddleware{BaseTykResponseHandler: baseHandler}
	}

	return nil
}

func handleResponseChain(chain []TykResponseHandler, rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) (abortRequest bool, err error) {

	if res.Request != nil {
		// res.Request context contains otel information from the otel roundtripper
		setContext(req, res.Request.Context())
	}

	traceIsEnabled := trace.IsEnabled()
	for _, rh := range chain {
		if err := handleResponse(rh, rw, res, req, ses, traceIsEnabled); err != nil {
			// Abort the request if this handler is a response middleware hook:
			if rh.Name() == "CustomMiddlewareResponseHook" {
				rh.HandleError(rw, req)
				return true, err
			}
			return false, err
		}
	}
	return false, nil
}

func handleResponse(rh TykResponseHandler, rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState, shouldTrace bool) error {
	if shouldTrace {
		span, ctx := trace.Span(req.Context(), rh.Name())
		defer span.Finish()
		req = req.WithContext(ctx)
	} else if rh.Base().Gw.GetConfig().OpenTelemetry.Enabled {
		return handleOtelTracedResponse(rh, rw, res, req, ses)
	}
	return rh.HandleResponse(rw, res, req, ses)
}

// handleOtelTracedResponse handles the tracing for the response middlewares when
// otel is enabled in the gateway
func handleOtelTracedResponse(rh TykResponseHandler, rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	var span otel.Span
	var err error

	baseMw := rh.Base()
	if baseMw == nil {
		return errors.New("unsupported base middleware")
	}

	// ResponseCacheMiddleware always executes but not always caches,so check if we must create the span
	shouldTrace := shouldPerformTracing(rh, baseMw)
	ctx := req.Context()
	if shouldTrace {
		if baseMw.Spec.DetailedTracing {
			ctx, span = baseMw.Gw.TracerProvider.Tracer().Start(ctx, rh.Name())
			defer span.End()
			setContext(req, ctx)
		} else {
			span = otel.SpanFromContext(ctx)
		}

		err = rh.HandleResponse(rw, res, req, ses)

		if err != nil {
			span.SetStatus(otel.SPAN_STATUS_ERROR, err.Error())
		}

		attrs := ctxGetSpanAttributes(req, rh.Name())
		if len(attrs) > 0 {
			span.SetAttributes(attrs...)
		}
	} else {
		err = rh.HandleResponse(rw, res, req, ses)
	}

	return err
}

func shouldPerformTracing(rh TykResponseHandler, baseMw *BaseTykResponseHandler) bool {
	return rh.Name() != "ResponseCacheMiddleware" || baseMw.Spec.CacheOptions.EnableCache
}

func parseForm(r *http.Request) {
	// https://golang.org/pkg/net/http/#Request.ParseForm
	// ParseForm drains the request body for a request with Content-Type of
	// application/x-www-form-urlencoded
	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" && r.Form == nil {
		var b bytes.Buffer
		r.Body = ioutil.NopCloser(io.TeeReader(r.Body, &b))

		r.ParseForm()

		r.Body = ioutil.NopCloser(&b)
		return
	}

	r.ParseForm()
}

type BaseTykResponseHandler struct {
	Spec *APISpec `json:"-"`
	Gw   *Gateway `json:"-"`
}

func (b *BaseTykResponseHandler) Enabled() bool {
	return true
}

func (b *BaseTykResponseHandler) Init(i interface{}, spec *APISpec) error {
	return nil
}

func (b *BaseTykResponseHandler) Name() string {
	return "BaseTykResponseHandler"
}

func (b *BaseTykResponseHandler) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	return nil
}

func (b *BaseTykResponseHandler) HandleError(writer http.ResponseWriter, h *http.Request) {}
