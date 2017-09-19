package main

import (
	"net/http"
	"sync"

	"errors"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/config"
)

var orgChanMap = make(map[string]chan bool)

type orgActiveMapMu struct {
	sync.RWMutex
	OrgMap map[string]bool
}

var orgActiveMap = orgActiveMapMu{
	OrgMap: map[string]bool{},
}

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
	if session.IsInactive {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": requestIP(r),
			"key":    k.Spec.OrgID,
		}).Warning("Organisation access is disabled.")

		return errors.New("this organisation access has been disabled, please contact your API administrator"), 403
	}

	// We found a session, apply the quota limiter
	reason := k.sessionlimiter.ForwardMessage(&session,
		k.Spec.OrgID,
		k.Spec.OrgSessionManager.Store(), false, false)

	k.Spec.OrgSessionManager.UpdateSession(k.Spec.OrgID, &session, getLifetime(k.Spec, &session))

	// org limits apply only to quotas, so we don't care about
	// sessionFailRateLimit.
	switch reason {
	case sessionFailNone:
	case sessionFailQuota:
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": requestIP(r),
			"key":    k.Spec.OrgID,
		}).Warning("Organisation quota has been exceeded.")

		// Fire a quota exceeded event
		k.FireEvent(EventOrgQuotaExceeded, EventQuotaExceededMeta{
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
		orgActiveMap.Lock()
		orgActiveMap.OrgMap[orgId] = isActive
		orgActiveMap.Unlock()
	}
}

func (k *OrganizationMonitor) ProcessRequestOffThread(r *http.Request) (error, int) {

	orgChan, ok := orgChanMap[k.Spec.OrgID]
	if !ok {
		orgChanMap[k.Spec.OrgID] = make(chan bool)
		orgChan = orgChanMap[k.Spec.OrgID]
		go k.SetOrgSentinel(orgChan, k.Spec.OrgID)
	}

	go k.AllowAccessNext(orgChan, r)

	orgActiveMap.RLock()
	active, found := orgActiveMap.OrgMap[k.Spec.OrgID]
	orgActiveMap.RUnlock()
	if found && !active {
		log.Debug("Is not active")
		return errors.New("This organisation access has been disabled or quota is exceeded, please contact your API administrator"), 403
	}

	log.Debug("Key not found")

	// Request is valid, carry on
	return nil, 200
}

func (k *OrganizationMonitor) AllowAccessNext(orgChan chan bool, r *http.Request) {

	session, found := k.OrgSession(k.Spec.OrgID)

	if !found {
		// No organisation session has been created, should not be a pre-requisite in site setups, so we pass the request on
		log.Debug("No session for org, skipping")
		return
	}

	// Is it active?
	if session.IsInactive {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": requestIP(r),
			"key":    k.Spec.OrgID,
		}).Warning("Organisation access is disabled.")

		//return errors.New("This organisation access has been disabled, please contact your API administrator."), 403
		orgChan <- false
		return
	}

	// We found a session, apply the quota limiter
	isQuotaExceeded := k.sessionlimiter.IsRedisQuotaExceeded(&session, k.Spec.OrgID, k.Spec.OrgSessionManager.Store())

	k.Spec.OrgSessionManager.UpdateSession(k.Spec.OrgID, &session, getLifetime(k.Spec, &session))

	if isQuotaExceeded {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": requestIP(r),
			"key":    k.Spec.OrgID,
		}).Warning("Organisation quota has been exceeded.")

		// Fire a quota exceeded event
		k.FireEvent(EventOrgQuotaExceeded, EventQuotaExceededMeta{
			EventMetaDefault: EventMetaDefault{Message: "Organisation quota has been exceeded", OriginatingRequest: EncodeRequestToEvent(r)},
			Path:             r.URL.Path,
			Origin:           requestIP(r),
			Key:              k.Spec.OrgID,
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
