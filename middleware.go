package main

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gocraft/health"
	"github.com/justinas/alice"
	"github.com/paulbellamy/ratecounter"
	cache "github.com/pmylund/go-cache"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"
)

const mwStatusRespond = 666

var GlobalRate = ratecounter.NewRateCounter(1 * time.Second)

type TykMiddleware interface {
	Init()
	Base() BaseMiddleware
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

	// Pull the configuration
	mwConf, err := mw.Config()
	if err != nil {
		log.Fatal("[Middleware] Configuration load failed")
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			job := instrument.NewJob("MiddlewareCall")
			meta := health.Kvs{
				"from_ip":  requestIP(r),
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

			if mw.Base().Spec.CORS.OptionsPassthrough && r.Method == "OPTIONS" {
				h.ServeHTTP(w, r)
				return
			}
			err, errCode := mw.ProcessRequest(w, r, mwConf)
			if err != nil {
				handler := ErrorHandler{mw.Base()}
				handler.HandleError(w, r, err.Error(), errCode)
				meta["error"] = err.Error()
				job.TimingKv("exec_time", time.Since(startTime).Nanoseconds(), meta)
				job.TimingKv(eventName+".exec_time", time.Since(startTime).Nanoseconds(), meta)
				return
			}

			// Special code, bypasses all other execution
			if errCode != mwStatusRespond {
				// No error, carry on...
				meta["bypass"] = "1"
				h.ServeHTTP(w, r)
			}

			job.TimingKv("exec_time", time.Since(startTime).Nanoseconds(), meta)
			job.TimingKv(eventName+".exec_time", time.Since(startTime).Nanoseconds(), meta)
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
	Spec  *APISpec
	Proxy ReturningHttpHandler
}

func (t BaseMiddleware) Base() BaseMiddleware { return t }

func (t BaseMiddleware) Init() {}
func (t BaseMiddleware) EnabledForSpec() bool {
	return true
}
func (t BaseMiddleware) Config() (interface{}, error) {
	return nil, nil
}

func (t BaseMiddleware) OrgSession(key string) (user.SessionState, bool) {
	// Try and get the session from the session store
	session, found := t.Spec.OrgSessionManager.SessionDetail(key)
	if found && config.Global.EnforceOrgDataAge {
		// If exists, assume it has been authorized and pass on
		// We cache org expiry data
		log.Debug("Setting data expiry: ", session.OrgID)
		go t.SetOrgExpiry(session.OrgID, session.DataExpires)
	}
	return session, found
}

func (t BaseMiddleware) SetOrgExpiry(orgid string, expiry int64) {
	ExpiryCache.Set(orgid, expiry, cache.DefaultExpiration)
}

func (t BaseMiddleware) OrgSessionExpiry(orgid string) int64 {
	log.Debug("Checking: ", orgid)
	cachedVal, found := ExpiryCache.Get(orgid)
	if !found {
		go t.OrgSession(orgid)
		log.Debug("no cached entry found, returning 7 days")
		return 604800
	}

	return cachedVal.(int64)
}

// ApplyPolicies will check if any policies are loaded. If any are, it
// will overwrite the session state to use the policy values.
func (t BaseMiddleware) ApplyPolicies(key string, session *user.SessionState) error {
	tags := make(map[string]bool)
	didQuota, didRateLimit, didACL := false, false, false
	policies := session.PolicyIDs()
	for i, polID := range policies {
		policiesMu.RLock()
		policy, ok := policiesByID[polID]
		policiesMu.RUnlock()
		if !ok {
			return fmt.Errorf("policy not found: %q", polID)
		}
		// Check ownership, policy org owner must be the same as API,
		// otherwise youcould overwrite a session key with a policy from a different org!
		if policy.OrgID != t.Spec.OrgID {
			return fmt.Errorf("attempting to apply policy from different organisation to key, skipping")
		}

		if policy.Partitions.Quota || policy.Partitions.RateLimit || policy.Partitions.Acl {
			// This is a partitioned policy, only apply what is active
			if policy.Partitions.Quota {
				if didQuota {
					return fmt.Errorf("cannot apply multiple quota policies")
				}
				didQuota = true
				// Quotas
				session.QuotaMax = policy.QuotaMax
				session.QuotaRenewalRate = policy.QuotaRenewalRate
			}

			if policy.Partitions.RateLimit {
				if didRateLimit {
					return fmt.Errorf("cannot apply multiple rate limit policies")
				}
				didRateLimit = true
				// Rate limting
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
					session.AccessRights = policy.AccessRights
					didACL = true
				} else { // second or later, merge
					for k, v := range policy.AccessRights {
						session.AccessRights[k] = v
					}
				}
				session.HMACEnabled = policy.HMACEnabled
			}

		} else {
			if len(policies) > 1 {
				return fmt.Errorf("cannot apply multiple policies if any are non-partitioned")
			}
			// This is not a partitioned policy, apply everything
			// Quotas
			session.QuotaMax = policy.QuotaMax
			session.QuotaRenewalRate = policy.QuotaRenewalRate

			// Rate limting
			session.Allowance = policy.Rate // This is a legacy thing, merely to make sure output is consistent. Needs to be purged
			session.Rate = policy.Rate
			session.Per = policy.Per
			if policy.LastUpdated != "" {
				session.LastUpdated = policy.LastUpdated
			}

			// ACL
			session.AccessRights = policy.AccessRights
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
	session.Tags = make([]string, 0, len(tags))
	for tag := range tags {
		session.Tags = append(session.Tags, tag)
	}
	// Update the session in the session manager in case it gets called again
	return t.Spec.SessionManager.UpdateSession(key, session, session.Lifetime(t.Spec.SessionLifetime))
}

// CheckSessionAndIdentityForValidKey will check first the Session store for a valid key, if not found, it will try
// the Auth Handler, if not found it will fail
func (t BaseMiddleware) CheckSessionAndIdentityForValidKey(key string) (user.SessionState, bool) {
	// Try and get the session from the session store
	log.Debug("Querying local cache")
	// Check in-memory cache
	if !config.Global.LocalSessionCache.DisableCacheSessionState {
		cachedVal, found := SessionCache.Get(key)
		if found {
			log.Debug("--> Key found in local cache")
			session := cachedVal.(user.SessionState)
			if err := t.ApplyPolicies(key, &session); err != nil {
				log.Error(err)
			}
			return session, true
		}
	}

	// Check session store
	log.Debug("Querying keystore")
	session, found := t.Spec.SessionManager.SessionDetail(key)
	if found {
		// If exists, assume it has been authorized and pass on
		// cache it
		go SessionCache.Set(key, session, cache.DefaultExpiration)

		// Check for a policy, if there is a policy, pull it and overwrite the session values
		if err := t.ApplyPolicies(key, &session); err != nil {
			log.Error(err)
		}
		log.Debug("--> Got key")
		return session, true
	}

	log.Debug("Querying authstore")
	// 2. If not there, get it from the AuthorizationHandler
	session, found = t.Spec.AuthManager.KeyAuthorised(key)
	if found {
		// If not in Session, and got it from AuthHandler, create a session with a new TTL
		log.Info("Recreating session for key: ", key)

		// cache it
		go SessionCache.Set(key, session, cache.DefaultExpiration)

		// Check for a policy, if there is a policy, pull it and overwrite the session values
		if err := t.ApplyPolicies(key, &session); err != nil {
			log.Error(err)
		}

		log.Debug("Lifetime is: ", session.Lifetime(t.Spec.SessionLifetime))
		// Need to set this in order for the write to work!
		session.LastUpdated = time.Now().String()
		t.Spec.SessionManager.UpdateSession(key, &session, session.Lifetime(t.Spec.SessionLifetime))
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
