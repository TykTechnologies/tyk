package main

import (
	"net/http"
	"sync"

	"errors"

	"github.com/TykTechnologies/tyk/config"
)

type orgChanMapMu struct {
	sync.Mutex
	channels map[string](chan bool)
}

var orgChanMap = orgChanMapMu{channels: map[string](chan bool){}}
var orgActiveMap sync.Map

// RateLimitAndQuotaCheck will check the incomming request and key whether it is within it's quota and
// within it's rate limit, it makes use of the SessionLimiter object to do this
type OrganizationMonitor struct {
	BaseMiddleware
	sessionlimiter SessionLimiter
	mon            Monitor
}

func (k *OrganizationMonitor) Name() string {
	return "OrganizationMonitor"
}

func (k *OrganizationMonitor) EnabledForSpec() bool {
	// If false, we aren't enforcing quotas so skip this mw
	// altogether
	return config.Global.EnforceOrgQuotas
}

func (k *OrganizationMonitor) ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) {
	if config.Global.ExperimentalProcessOrgOffThread {
		return k.ProcessRequestOffThread(r)
	}
	return k.ProcessRequestLive(r)
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *OrganizationMonitor) ProcessRequestLive(r *http.Request) (error, int) {

	session, found := k.OrgSession(k.Spec.OrgID)
	if !found {
		// No organisation session has been created, should not be a pre-requisite in site setups, so we pass the request on
		return nil, 200
	}

	// Is it active?
	logEntry := getLogEntryForRequest(r, k.Spec.OrgID, nil)
	if session.IsInactive {
		logEntry.Warning("Organisation access is disabled.")

		return errors.New("this organisation access has been disabled, please contact your API administrator"), 403
	}

	// We found a session, apply the quota limiter
	reason := k.sessionlimiter.ForwardMessage(&session,
		k.Spec.OrgID,
		k.Spec.OrgSessionManager.Store(), false, false)

	k.Spec.OrgSessionManager.UpdateSession(k.Spec.OrgID, &session, session.Lifetime(k.Spec.SessionLifetime), false)

	// org limits apply only to quotas, so we don't care about
	// sessionFailRateLimit.
	switch reason {
	case sessionFailNone:
	case sessionFailQuota:
		logEntry.Warning("Organisation quota has been exceeded.")

		// Fire a quota exceeded event
		k.FireEvent(EventOrgQuotaExceeded, EventKeyFailureMeta{
			EventMetaDefault: EventMetaDefault{Message: "Organisation quota has been exceeded", OriginatingRequest: EncodeRequestToEvent(r)},
			Path:             r.URL.Path,
			Origin:           requestIP(r),
			Key:              k.Spec.OrgID,
		})

		return errors.New("This organisation quota has been exceeded, please contact your API administrator"), 403
	}

	if config.Global.Monitor.MonitorOrgKeys {
		// Run the trigger monitor
		k.mon.Check(&session, "")
	}

	// Lets keep a reference of the org
	setCtxValue(r, OrgSessionContext, session)

	// Request is valid, carry on
	return nil, 200
}

func (k *OrganizationMonitor) SetOrgSentinel(orgChan chan bool, orgId string) {
	for isActive := range orgChan {
		log.Debug("Chan got:", isActive)
		o, ok := orgActiveMap.Load(orgId)
		if ok {
			o = isActive
			orgActiveMap.Store(orgId, o)
		}
	}
}

func (k *OrganizationMonitor) ProcessRequestOffThread(r *http.Request) (error, int) {
	orgChanMap.Lock()
	orgChan, ok := orgChanMap.channels[k.Spec.OrgID]
	if !ok {
		orgChan = make(chan bool)
		orgChanMap.channels[k.Spec.OrgID] = orgChan
		go k.SetOrgSentinel(orgChan, k.Spec.OrgID)
	}
	orgChanMap.Unlock()
	active, found := orgActiveMap.Load(k.Spec.OrgID)

	go k.AllowAccessNext(orgChan, r.URL.Path, requestIP(r), r)

	if found && !active.(bool) {
		log.Debug("Is not active")
		return errors.New("This organisation access has been disabled or quota is exceeded, please contact your API administrator"), 403
	}

	log.Debug("Key not found")

	// Request is valid, carry on
	return nil, 200
}

func (k *OrganizationMonitor) AllowAccessNext(orgChan chan bool, path string, IP string, r *http.Request) {

	session, found := k.OrgSession(k.Spec.OrgID)

	if !found {
		// No organisation session has been created, should not be a pre-requisite in site setups, so we pass the request on
		log.Debug("No session for org, skipping")
		return
	}

	// Is it active?
	logEntry := getExplicitLogEntryForRequest(path, IP, k.Spec.OrgID, nil)
	if session.IsInactive {
		logEntry.Warning("Organisation access is disabled.")

		//return errors.New("This organisation access has been disabled, please contact your API administrator."), 403
		orgChan <- false
		return
	}

	// We found a session, apply the quota limiter
	isQuotaExceeded := k.sessionlimiter.RedisQuotaExceeded(&session, k.Spec.OrgID, k.Spec.OrgSessionManager.Store())

	k.Spec.OrgSessionManager.UpdateSession(k.Spec.OrgID, &session, session.Lifetime(k.Spec.SessionLifetime), false)

	if isQuotaExceeded {
		logEntry.Warning("Organisation quota has been exceeded.")

		// Fire a quota exceeded event
		k.FireEvent(EventOrgQuotaExceeded, EventKeyFailureMeta{
			EventMetaDefault: EventMetaDefault{
				Message: "Organisation quota has been exceeded"},
			Path:   path,
			Origin: IP,
			Key:    k.Spec.OrgID,
		})

		//return errors.New("This organisation quota has been exceeded, please contact your API administrator"), 403
		orgChan <- false

		if config.Global.Monitor.MonitorOrgKeys {
			// Run the trigger monitor
			k.mon.Check(&session, "")
		}

		return
	}

	if config.Global.Monitor.MonitorOrgKeys {
		// Run the trigger monitor
		k.mon.Check(&session, "")
	}

	// Lets keep a reference of the org
	setCtxValue(r, OrgSessionContext, session)

	orgChan <- true
}
