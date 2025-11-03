package gateway

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/request"
	"github.com/TykTechnologies/tyk/user"
)

type orgChanMapMu struct {
	sync.Mutex
	channels map[string](chan bool)
}

var orgChanMap = orgChanMapMu{channels: map[string](chan bool){}}
var orgActiveMap sync.Map

// orgCacheEntry holds org session with soft and hard expiry times
type orgCacheEntry struct {
	session    user.SessionState
	softExpiry int64
	hardExpiry int64
}

var orgSessionCache sync.Map
var orgRefreshInProgress sync.Map // prevents multiple concurrent refreshes

// Cache expiry durations for org sessions
const (
	orgSessionSoftExpiry   = 10 * time.Minute
	orgSessionHardExpiry   = 1 * time.Hour
	orgSessionFetchTimeout = 2 * time.Second
)

// RateLimitAndQuotaCheck will check the incoming request and key whether it is within it's quota and
// within it's rate limit, it makes use of the SessionLimiter object to do this
type OrganizationMonitor struct {
	*BaseMiddleware

	sessionlimiter SessionLimiter
	mon            Monitor
}

func (k *OrganizationMonitor) Name() string {
	return "OrganizationMonitor"
}

func (k *OrganizationMonitor) EnabledForSpec() bool {
	// If false, we aren't enforcing quotas so skip this mw
	// altogether
	return k.Spec.GlobalConfig.EnforceOrgQuotas
}

func (k *OrganizationMonitor) getOrgHasNoSession() bool {
	k.Spec.RLock()
	defer k.Spec.RUnlock()
	return k.Spec.OrgHasNoSession
}

func (k *OrganizationMonitor) setOrgHasNoSession(val bool) {
	k.Spec.Lock()
	defer k.Spec.Unlock()
	k.Spec.OrgHasNoSession = val
}

func (k *OrganizationMonitor) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	// Skip rate limiting and quotas for looping
	if !ctxCheckLimits(r) {
		return nil, http.StatusOK
	}

	// short path for specs which have organization limiter enabled but organization has no session
	if k.getOrgHasNoSession() {
		return nil, http.StatusOK
	}

	var orgSession user.SessionState
	var found bool

	// try to check in in-app cache 1st
	if !k.Spec.GlobalConfig.LocalSessionCache.DisableCacheSessionState {
		var cachedSession interface{}
		if cachedSession, found = k.Gw.SessionCache.Get(k.Spec.OrgID); found {
			sess := cachedSession.(user.SessionState)
			orgSession = sess.Clone()
		}
	}

	if !found {
		orgSession, found = k.getOrgSessionWithStaleWhileRevalidate()
		if !found {
			k.setOrgHasNoSession(true)
			return nil, http.StatusOK
		}
	}
	clone := orgSession.Clone()
	if k.Spec.GlobalConfig.ExperimentalProcessOrgOffThread {
		// Make a copy of request before before sending to goroutine
		r2 := r.WithContext(r.Context())
		return k.ProcessRequestOffThread(r2, &clone)
	}
	return k.ProcessRequestLive(r, &clone)
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *OrganizationMonitor) ProcessRequestLive(r *http.Request, orgSession *user.SessionState) (error, int) {
	logger := k.Logger()

	if orgSession.IsInactive {
		logger.Warning("Organisation access is disabled.")

		return errors.New("this organisation access has been disabled, please contact your API administrator"), http.StatusForbidden
	}

	// We found a session, apply the quota and rate limiter
	reason := k.Gw.SessionLimiter.ForwardMessage(
		r,
		orgSession,
		k.Spec.OrgID,
		"",
		k.Spec.OrgSessionManager.Store(),
		orgSession.Per > 0 && orgSession.Rate > 0,
		true,
		k.Spec,
		false,
	)

	sessionLifeTime := orgSession.Lifetime(k.Spec.GetSessionLifetimeRespectsKeyExpiration(), k.Spec.SessionLifetime, k.Gw.GetConfig().ForceGlobalSessionLifetime, k.Gw.GetConfig().GlobalSessionLifetime)

	if err := k.Spec.OrgSessionManager.UpdateSession(k.Spec.OrgID, orgSession, sessionLifeTime, false); err == nil {
		// update in-app cache if needed
		if !k.Spec.GlobalConfig.LocalSessionCache.DisableCacheSessionState {
			k.Gw.SessionCache.Set(k.Spec.OrgID, orgSession.Clone(), sessionLifeTime)
		}
	} else {
		logger.WithError(err).Error("Could not update org session")
	}

	switch reason {
	case sessionFailNone:
		// all good, keep org active
	case sessionFailQuota:
		logger.Warning("Organisation quota has been exceeded.", k.Spec.OrgID)

		// Fire a quota exceeded event
		k.FireEvent(
			EventOrgQuotaExceeded,
			EventKeyFailureMeta{
				EventMetaDefault: EventMetaDefault{
					Message:            "Organisation quota has been exceeded",
					OriginatingRequest: EncodeRequestToEvent(r),
				},
				Path:   r.URL.Path,
				Origin: request.RealIP(r),
				Key:    k.Spec.OrgID,
			})

		return errors.New("This organisation quota has been exceeded, please contact your API administrator"), http.StatusForbidden
	case sessionFailRateLimit:
		logger.Warning("Organisation rate limit has been exceeded.", k.Spec.OrgID)

		// Fire a rate limit exceeded event
		k.FireEvent(
			EventOrgRateLimitExceeded,
			EventKeyFailureMeta{
				EventMetaDefault: EventMetaDefault{
					Message:            "Organisation rate limit has been exceeded",
					OriginatingRequest: EncodeRequestToEvent(r),
				},
				Path:   r.URL.Path,
				Origin: request.RealIP(r),
				Key:    k.Spec.OrgID,
			},
		)
		return errors.New("This organisation rate limit has been exceeded, please contact your API administrator"), http.StatusForbidden
	}

	if k.Spec.GlobalConfig.Monitor.MonitorOrgKeys {
		// Run the trigger monitor
		k.mon.Check(orgSession, "")
	}

	// Lets keep a reference of the org
	setCtxValue(r, ctx.OrgSessionContext, orgSession)

	// Request is valid, carry on
	return nil, http.StatusOK
}

func (k *OrganizationMonitor) SetOrgSentinel(orgChan chan bool, orgId string) {
	for isActive := range orgChan {
		k.Logger().Debug("Chan got:", isActive)
		orgActiveMap.Store(orgId, isActive)
	}
}

func (k *OrganizationMonitor) ProcessRequestOffThread(r *http.Request, orgSession *user.SessionState) (error, int) {
	orgChanMap.Lock()
	orgChan, ok := orgChanMap.channels[k.Spec.OrgID]
	if !ok {
		orgChan = make(chan bool)
		orgChanMap.channels[k.Spec.OrgID] = orgChan
		go k.SetOrgSentinel(orgChan, k.Spec.OrgID)
	}
	orgChanMap.Unlock()
	active, found := orgActiveMap.Load(k.Spec.OrgID)

	// Lets keep a reference of the org
	// session might be updated by go-routine AllowAccessNext and we loose those changes here
	// but it is OK as we need it in context for detailed org logging
	clone := orgSession.Clone()
	setCtxValue(r, ctx.OrgSessionContext, &clone)

	orgSessionCopy := orgSession.Clone()
	go k.AllowAccessNext(
		orgChan,
		r.URL.Path,
		request.RealIP(r),
		r,
		&orgSessionCopy,
	)

	if found && !active.(bool) {
		k.Logger().Debug("Is not active")
		return errors.New("This organization access has been disabled or quota/rate limit is exceeded, please contact your API administrator"), http.StatusForbidden
	}

	// Request is valid, carry on
	return nil, http.StatusOK
}

func (k *OrganizationMonitor) AllowAccessNext(
	orgChan chan bool,
	path string,
	IP string,
	r *http.Request,
	session *user.SessionState) {

	// Is it active?
	logEntry := k.Gw.getExplicitLogEntryForRequest(k.Logger(), path, IP, k.Spec.OrgID, nil)
	if session.IsInactive {
		logEntry.Warning("Organisation access is disabled.")
		orgChan <- false
		return
	}

	customQuotaKey := ""

	// We found a session, apply the quota and rate limiter
	reason := k.Gw.SessionLimiter.ForwardMessage(
		r,
		session,
		k.Spec.OrgID,
		customQuotaKey,
		k.Spec.OrgSessionManager.Store(),
		session.Per > 0 && session.Rate > 0,
		true,
		k.Spec,
		false,
	)

	sessionLifeTime := session.Lifetime(k.Spec.GetSessionLifetimeRespectsKeyExpiration(), k.Spec.SessionLifetime, k.Gw.GetConfig().ForceGlobalSessionLifetime, k.Gw.GetConfig().GlobalSessionLifetime)

	if err := k.Spec.OrgSessionManager.UpdateSession(k.Spec.OrgID, session, sessionLifeTime, false); err == nil {
		// update in-app cache if needed
		if !k.Spec.GlobalConfig.LocalSessionCache.DisableCacheSessionState {
			k.Gw.SessionCache.Set(k.Spec.OrgID, session.Clone(), sessionLifeTime)
		}
	} else {
		logEntry.WithError(err).WithField("orgID", k.Spec.OrgID).Error("Could not update org session")
	}

	isExceeded := false
	switch reason {
	case sessionFailNone:
		// all good, keep org active
	case sessionFailQuota:
		isExceeded = true

		logEntry.Warning("Organisation quota has been exceeded.")

		// Fire a quota exceeded event
		k.FireEvent(
			EventOrgQuotaExceeded,
			EventKeyFailureMeta{
				EventMetaDefault: EventMetaDefault{
					Message: "Organisation quota has been exceeded",
				},
				Path:   path,
				Origin: IP,
				Key:    k.Spec.OrgID,
			},
		)
	case sessionFailRateLimit:
		isExceeded = true

		logEntry.Warning("Organisation rate limit has been exceeded.")

		// Fire a rate limit exceeded event
		k.FireEvent(
			EventOrgRateLimitExceeded,
			EventKeyFailureMeta{
				EventMetaDefault: EventMetaDefault{
					Message: "Organisation rate limit has been exceeded",
				},
				Path:   path,
				Origin: IP,
				Key:    k.Spec.OrgID,
			},
		)
	}

	if k.Spec.GlobalConfig.Monitor.MonitorOrgKeys {
		// Run the trigger monitor
		k.mon.Check(session, "")
	}

	if isExceeded {
		orgChan <- false
		return
	}

	orgChan <- true
}

// fetchOrgSessionWithTimeout fetches org session with a timeout to prevent hanging
func (k *OrganizationMonitor) fetchOrgSessionWithTimeout() (user.SessionState, bool) {
	timeoutCtx, cancel := context.WithTimeout(context.Background(), orgSessionFetchTimeout)
	defer cancel()

	type result struct {
		session user.SessionState
		found   bool
	}
	resultChan := make(chan result, 1)

	go func() {
		session, found := k.OrgSession(k.Spec.OrgID)
		select {
		case resultChan <- result{session: session, found: found}:
		case <-timeoutCtx.Done():
			return
		}
	}()

	select {
	case res := <-resultChan:
		return res.session, res.found
	case <-timeoutCtx.Done():
		return user.SessionState{}, false
	}
}

// getOrgSessionWithStaleWhileRevalidate implements stale-while-revalidate pattern:
// - Soft expiry (10 min): Return stale data, trigger background refresh
// - Hard expiry (1 hour): Try to fetch fresh data, fall back to allowing request
func (k *OrganizationMonitor) getOrgSessionWithStaleWhileRevalidate() (user.SessionState, bool) {
	now := time.Now().UnixNano()

	if cached, ok := orgSessionCache.Load(k.Spec.OrgID); ok {
		entry, ok := cached.(*orgCacheEntry)
		if !ok {
			k.Logger().Error("Invalid cache entry type")
			orgSessionCache.Delete(k.Spec.OrgID)
			return user.SessionState{}, false
		}

		if now < entry.softExpiry {
			k.Logger().Debug("Using fresh org session from cache")
			return entry.session.Clone(), true
		}

		if now < entry.hardExpiry {
			k.Logger().Debug("Using stale org session, triggering background refresh")

			if _, inProgress := orgRefreshInProgress.LoadOrStore(k.Spec.OrgID, true); !inProgress {
				go k.refreshOrgSession()
			}

			return entry.session.Clone(), true
		}

		k.Logger().Debug("Org session beyond hard expiry, removing from cache")
		orgSessionCache.Delete(k.Spec.OrgID)
	}

	k.Logger().Debug("No cached org session, attempting fresh fetch with timeout")
	session, found := k.fetchOrgSessionWithTimeout()

	if !found {
		k.Logger().Warning("Org session fetch timed out after 2s")
		return user.SessionState{}, false
	}

	k.cacheOrgSession(session)
	return session, true
}

// refreshOrgSession refreshes org session in the background
func (k *OrganizationMonitor) refreshOrgSession() {
	defer orgRefreshInProgress.Delete(k.Spec.OrgID)

	k.Logger().Debug("Background refresh started for org session")

	session, found := k.fetchOrgSessionWithTimeout()

	if !found {
		k.Logger().Warning("Background refresh timed out after 2s")
		return
	}

	k.cacheOrgSession(session)
	k.Logger().Debug("Background refresh completed successfully")
}

// cacheOrgSession stores org session with soft and hard expiry
func (k *OrganizationMonitor) cacheOrgSession(session user.SessionState) {
	now := time.Now()
	entry := &orgCacheEntry{
		session:    session.Clone(),
		softExpiry: now.Add(orgSessionSoftExpiry).UnixNano(),
		hardExpiry: now.Add(orgSessionHardExpiry).UnixNano(),
	}

	orgSessionCache.Store(k.Spec.OrgID, entry)
	k.Logger().Debug("Cached org session")
}
