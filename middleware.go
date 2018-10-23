package main

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/gocraft/health"
	"github.com/justinas/alice"
	newrelic "github.com/newrelic/go-agent"
	"github.com/paulbellamy/ratecounter"
	cache "github.com/pmylund/go-cache"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/request"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

const mwStatusRespond = 666

var GlobalRate = ratecounter.NewRateCounter(1 * time.Second)

type TykMiddleware interface {
	Init()
	Base() *BaseMiddleware
	SetName(string)
	SetRequestLogger(*http.Request)
	Logger() *logrus.Entry
	Config() (interface{}, error)
	ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) // Handles request
	EnabledForSpec() bool
	Name() string
}

func createDynamicMiddleware(name string, isPre, useSession bool, baseMid BaseMiddleware) func(http.Handler) http.Handler {
	dMiddleware := &DynamicMiddleware{
		BaseMiddleware:      baseMid,
		MiddlewareClassName: name,
		Pre:                 isPre,
		UseSession:          useSession,
	}

	return createMiddleware(dMiddleware)
}

// Generic middleware caller to make extension easier
func createMiddleware(mw TykMiddleware) func(http.Handler) http.Handler {
	// construct a new instance
	mw.Init()
	mw.SetName(mw.Name())
	mw.Logger().Debug("Init")

	// Pull the configuration
	mwConf, err := mw.Config()
	if err != nil {
		mw.Logger().Fatal("[Middleware] Configuration load failed")
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mw.SetRequestLogger(r)

			if config.Global().NewRelic.AppName != "" {
				if txn, ok := w.(newrelic.Transaction); ok {
					defer newrelic.StartSegment(txn, mw.Name()).End()
				}
			}

			job := instrument.NewJob("MiddlewareCall")
			meta := health.Kvs{
				"from_ip":  request.RealIP(r),
				"method":   r.Method,
				"endpoint": r.URL.Path,
				"raw_url":  r.URL.String(),
				"size":     strconv.Itoa(int(r.ContentLength)),
				"mw_name":  mw.Name(),
			}
			eventName := mw.Name() + "." + "executed"
			job.EventKv("executed", meta)
			job.EventKv(eventName, meta)
			startTime := time.Now()
			mw.Logger().WithField("ts", startTime.UnixNano()).Debug("Started")

			if mw.Base().Spec.CORS.OptionsPassthrough && r.Method == "OPTIONS" {
				h.ServeHTTP(w, r)
				return
			}
			err, errCode := mw.ProcessRequest(w, r, mwConf)
			if err != nil {
				handler := ErrorHandler{*mw.Base()}
				handler.HandleError(w, r, err.Error(), errCode)

				meta["error"] = err.Error()

				finishTime := time.Since(startTime)
				job.TimingKv("exec_time", finishTime.Nanoseconds(), meta)
				job.TimingKv(eventName+".exec_time", finishTime.Nanoseconds(), meta)

				mw.Logger().WithError(err).WithField("code", errCode).WithField("ns", finishTime.Nanoseconds()).Debug("Finished")
				return
			}

			finishTime := time.Since(startTime)
			job.TimingKv("exec_time", finishTime.Nanoseconds(), meta)
			job.TimingKv(eventName+".exec_time", finishTime.Nanoseconds(), meta)
			mw.Logger().WithField("code", errCode).WithField("ns", finishTime.Nanoseconds()).Debug("Finished")

			// Special code, bypasses all other execution
			if errCode != mwStatusRespond {
				// No error, carry on...
				meta["bypass"] = "1"
				h.ServeHTTP(w, r)
			} else {
				mw.Base().UpdateRequestSession(r)
			}
		})
	}
}

func mwAppendEnabled(chain *[]alice.Constructor, mw TykMiddleware) bool {
	if mw.EnabledForSpec() {
		*chain = append(*chain, createMiddleware(mw))
		return true
	}
	return false
}

func mwList(mws ...TykMiddleware) []alice.Constructor {
	var list []alice.Constructor
	for _, mw := range mws {
		mwAppendEnabled(&list, mw)
	}
	return list
}

// BaseMiddleware wraps up the ApiSpec and Proxy objects to be included in a
// middleware handler, this can probably be handled better.
type BaseMiddleware struct {
	Spec   *APISpec
	Proxy  ReturningHttpHandler
	logger *logrus.Entry
}

func (t BaseMiddleware) Base() *BaseMiddleware { return &t }

func (t BaseMiddleware) Logger() (logger *logrus.Entry) {
	if t.logger == nil {
		t.logger = logrus.NewEntry(log)
	}

	return t.logger
}

func (t *BaseMiddleware) SetName(name string) {
	t.logger = t.Logger().WithField("mw", name)
}

func (t *BaseMiddleware) SetRequestLogger(r *http.Request) {
	t.logger = getLogEntryForRequest(t.Logger(), r, ctxGetAuthToken(r), nil)
}

func (t BaseMiddleware) Init() {}
func (t BaseMiddleware) EnabledForSpec() bool {
	return true
}
func (t BaseMiddleware) Config() (interface{}, error) {
	return nil, nil
}

func (t BaseMiddleware) OrgSession(key string) (user.SessionState, bool) {
	// Try and get the session from the session store
	session, found := t.Spec.OrgSessionManager.SessionDetail(key, false)
	if found && t.Spec.GlobalConfig.EnforceOrgDataAge {
		// If exists, assume it has been authorized and pass on
		// We cache org expiry data
		t.Logger().Debug("Setting data expiry: ", session.OrgID)
		go t.SetOrgExpiry(session.OrgID, session.DataExpires)
	}

	session.SetKeyHash(storage.HashKey(key))
	return session, found
}

func (t BaseMiddleware) SetOrgExpiry(orgid string, expiry int64) {
	ExpiryCache.Set(orgid, expiry, cache.DefaultExpiration)
}

func (t BaseMiddleware) OrgSessionExpiry(orgid string) int64 {
	t.Logger().Debug("Checking: ", orgid)
	cachedVal, found := ExpiryCache.Get(orgid)
	if !found {
		go t.OrgSession(orgid)
		t.Logger().Debug("no cached entry found, returning 7 days")
		return 604800
	}

	return cachedVal.(int64)
}

func (t BaseMiddleware) UpdateRequestSession(r *http.Request) bool {
	session := ctxGetSession(r)
	token := ctxGetAuthToken(r)

	if session == nil || token == "" {
		return false
	}

	if !ctxSessionUpdateScheduled(r) {
		return false
	}

	lifetime := session.Lifetime(t.Spec.SessionLifetime)
	if err := t.Spec.SessionManager.UpdateSession(token, session, lifetime, false); err != nil {
		t.Logger().WithError(err).Error("Can't update session")
		return false
	}

	// Set context state back
	// Useful for benchmarks when request object stays same
	ctxDisableSessionUpdate(r)

	if !t.Spec.GlobalConfig.LocalSessionCache.DisableCacheSessionState {
		SessionCache.Set(session.KeyHash(), *session, cache.DefaultExpiration)
	}

	return true
}

// ApplyPolicies will check if any policies are loaded. If any are, it
// will overwrite the session state to use the policy values.
func (t BaseMiddleware) ApplyPolicies(key string, session *user.SessionState) error {
	rights := session.AccessRights
	if rights == nil {
		rights = make(map[string]user.AccessDefinition)
	}
	tags := make(map[string]bool)
	didQuota, didRateLimit, didACL := false, false, false
	didPerAPI := make(map[string]bool)
	policies := session.PolicyIDs()
	for i, polID := range policies {
		policiesMu.RLock()
		policy, ok := policiesByID[polID]
		policiesMu.RUnlock()
		if !ok {
			err := fmt.Errorf("policy not found: %q", polID)
			t.Logger().Error(err)
			return err
		}
		// Check ownership, policy org owner must be the same as API,
		// otherwise youcould overwrite a session key with a policy from a different org!
		if t.Spec != nil && policy.OrgID != t.Spec.OrgID {
			err := fmt.Errorf("attempting to apply policy from different organisation to key, skipping")
			t.Logger().Error(err)
			return err
		}

		if policy.Partitions.PerAPI &&
			(policy.Partitions.Quota || policy.Partitions.RateLimit || policy.Partitions.Acl) {
			err := fmt.Errorf("cannot apply policy %s which has per_api and any of partitions set", policy.ID)
			log.Error(err)
			return err
		}

		if policy.Partitions.PerAPI {
			// new logic when you can specify quota or rate in more than one policy but for different APIs
			if didQuota || didRateLimit || didACL { // no other partitions allowed
				err := fmt.Errorf("cannot apply multiple policies when some have per_api set and some are partitioned")
				log.Error(err)
				return err
			}
			for apiID, accessRights := range policy.AccessRights {
				// check if limit was already set for this API by other policy assigned to key
				if didPerAPI[apiID] {
					err := fmt.Errorf("cannot apply multiple policies for API: %s", apiID)
					log.Error(err)
					return err
				}

				// check if we already have limit on API level specified when policy was created
				if accessRights.Limit == nil {
					// limit was not specified on API level so we will populate it from policy
					accessRights.Limit = &user.APILimit{
						QuotaMax:         policy.QuotaMax,
						QuotaRenewalRate: policy.QuotaRenewalRate,
						Rate:             policy.Rate,
						Per:              policy.Per,
						SetByPolicy:      true,
					}
				}

				// adjust policy access right with limit on API level
				policy.AccessRights[apiID] = accessRights

				// overwrite session access right for this API
				rights[apiID] = accessRights

				// identify that limit for that API is set (to allow set it only once)
				didPerAPI[apiID] = true
			}
		} else if policy.Partitions.Quota || policy.Partitions.RateLimit || policy.Partitions.Acl {
			// This is a partitioned policy, only apply what is active
			// legacy logic when you can specify quota or rate only in no more than one policy
			if len(didPerAPI) > 0 { // no policies with per_api set allowed
				err := fmt.Errorf("cannot apply multiple policies when some are partitioned and some have per_api set")
				log.Error(err)
				return err
			}
			if policy.Partitions.Quota {
				if didQuota {
					err := fmt.Errorf("cannot apply multiple quota policies")
					t.Logger().Error(err)
					return err
				}
				didQuota = true
				// Quotas
				session.QuotaMax = policy.QuotaMax
				session.QuotaRenewalRate = policy.QuotaRenewalRate
			}

			if policy.Partitions.RateLimit {
				if didRateLimit {
					err := fmt.Errorf("cannot apply multiple rate limit policies")
					t.Logger().Error(err)
					return err
				}
				didRateLimit = true
				// Rate limiting
				session.Allowance = policy.Rate // This is a legacy thing, merely to make sure output is consistent. Needs to be purged
				session.Rate = policy.Rate
				session.Per = policy.Per
				if policy.LastUpdated != "" {
					session.LastUpdated = policy.LastUpdated
				}
			}

			if policy.Partitions.Acl {
				// ACL
				if !didACL { // first, overwrite rights
					rights = make(map[string]user.AccessDefinition)
					didACL = true
				}
				// Second or later, merge
				for k, v := range policy.AccessRights {
					rights[k] = v
				}
				session.HMACEnabled = policy.HMACEnabled
			}
		} else {
			if len(policies) > 1 {
				err := fmt.Errorf("cannot apply multiple policies if any are non-partitioned")
				t.Logger().Error(err)
				return err
			}
			// This is not a partitioned policy, apply everything
			// Quotas
			session.QuotaMax = policy.QuotaMax
			session.QuotaRenewalRate = policy.QuotaRenewalRate

			// Rate limiting
			session.Allowance = policy.Rate // This is a legacy thing, merely to make sure output is consistent. Needs to be purged
			session.Rate = policy.Rate
			session.Per = policy.Per
			if policy.LastUpdated != "" {
				session.LastUpdated = policy.LastUpdated
			}

			// ACL
			rights = policy.AccessRights
			session.HMACEnabled = policy.HMACEnabled
		}

		// Required for all
		if i == 0 { // if any is true, key is inactive
			session.IsInactive = policy.IsInactive
		} else if policy.IsInactive {
			session.IsInactive = true
		}
		for _, tag := range policy.Tags {
			tags[tag] = true
		}
	}

	// set tags
	if len(tags) > 0 {
		session.Tags = make([]string, 0, len(tags))
		for tag := range tags {
			session.Tags = append(session.Tags, tag)
		}
	}

	session.AccessRights = rights

	return nil
}

// CheckSessionAndIdentityForValidKey will check first the Session store for a valid key, if not found, it will try
// the Auth Handler, if not found it will fail
func (t BaseMiddleware) CheckSessionAndIdentityForValidKey(key string, r *http.Request) (user.SessionState, bool) {
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
	cacheKey := key
	if t.Spec.GlobalConfig.HashKeys {
		cacheKey = storage.HashStr(key)
	}

	// Check in-memory cache
	if !t.Spec.GlobalConfig.LocalSessionCache.DisableCacheSessionState {
		cachedVal, found := SessionCache.Get(cacheKey)
		if found {
			t.Logger().Debug("--> Key found in local cache")
			session := cachedVal.(user.SessionState)
			if err := t.ApplyPolicies(key, &session); err != nil {
				t.Logger().Error(err)
				return session, false
			}
			return session, true
		}
	}

	// Check session store
	t.Logger().Debug("Querying keystore")
	session, found := t.Spec.SessionManager.SessionDetail(key, false)
	if found {
		session.SetKeyHash(cacheKey)
		// If exists, assume it has been authorized and pass on
		// cache it
		if !t.Spec.GlobalConfig.LocalSessionCache.DisableCacheSessionState {
			go SessionCache.Set(cacheKey, session, cache.DefaultExpiration)
		}

		// Check for a policy, if there is a policy, pull it and overwrite the session values
		if err := t.ApplyPolicies(key, &session); err != nil {
			t.Logger().Error(err)
			return session, false
		}
		t.Logger().Debug("Got key")
		return session, true
	}

	t.Logger().Debug("Querying authstore")
	// 2. If not there, get it from the AuthorizationHandler
	session, found = t.Spec.AuthManager.KeyAuthorised(key)
	if found {
		session.SetKeyHash(cacheKey)
		// If not in Session, and got it from AuthHandler, create a session with a new TTL
		t.Logger().Info("Recreating session for key: ", key)

		// cache it
		if !t.Spec.GlobalConfig.LocalSessionCache.DisableCacheSessionState {
			go SessionCache.Set(cacheKey, session, cache.DefaultExpiration)
		}

		// Check for a policy, if there is a policy, pull it and overwrite the session values
		if err := t.ApplyPolicies(key, &session); err != nil {
			t.Logger().Error(err)
			return session, false
		}

		t.Logger().Debug("Lifetime is: ", session.Lifetime(t.Spec.SessionLifetime))
		ctxScheduleSessionUpdate(r)
	}

	return session, found
}

// FireEvent is added to the BaseMiddleware object so it is available across the entire stack
func (t BaseMiddleware) FireEvent(name apidef.TykEvent, meta interface{}) {
	fireEvent(name, meta, t.Spec.EventPaths)
}

type TykResponseHandler interface {
	Init(interface{}, *APISpec) error
	HandleResponse(http.ResponseWriter, *http.Response, *http.Request, *user.SessionState) error
}

func responseProcessorByName(name string) TykResponseHandler {
	switch name {
	case "header_injector":
		return &HeaderInjector{}
	case "response_body_transform":
		return &ResponseTransformMiddleware{}
	case "response_body_transform_jq":
		return &ResponseTransformJQMiddleware{}
	case "header_transform":
		return &HeaderTransform{}
	}
	return nil
}

func handleResponseChain(chain []TykResponseHandler, rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	for _, rh := range chain {
		if err := rh.HandleResponse(rw, res, req, ses); err != nil {
			return err
		}
	}
	return nil
}
