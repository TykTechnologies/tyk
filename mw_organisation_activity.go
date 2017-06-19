package main

import (
	"net/http"
	"sync"

	"errors"

	"github.com/gorilla/context"

	"github.com/Sirupsen/logrus"
)

var orgChanMap = make(map[string]chan bool)

type orgActiveMapMu struct {
	sync.RWMutex
	OrgMap map[string]bool
}

var orgActiveMap = orgActiveMapMu{
	OrgMap: make(map[string]bool),
}

// RateLimitAndQuotaCheck will check the incomming request and key whether it is within it's quota and
// within it's rate limit, it makes use of the SessionLimiter object to do this
type OrganizationMonitor struct {
	*TykMiddleware
	sessionlimiter SessionLimiter
	mon            Monitor
}

func (k *OrganizationMonitor) GetName() string {
	return "OrganizationMonitor"
}

// New lets you do any initialisations for the object can be done here
func (k *OrganizationMonitor) New() {
	k.sessionlimiter = SessionLimiter{}
	k.mon = Monitor{}
}

func (k *OrganizationMonitor) IsEnabledForSpec() bool {
	// If false, we aren't enforcing quotas so skip this mw
	// altogether
	return config.EnforceOrgQuotas
}

func (k *OrganizationMonitor) ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) {
	if config.ExperimentalProcessOrgOffThread {
		return k.ProcessRequestOffThread(w, r, conf)
	}
	return k.ProcessRequestLive(w, r, conf)
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *OrganizationMonitor) ProcessRequestLive(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {

	if !config.EnforceOrgQuotas {
		// We aren;t enforcing quotas, so skip this altogether
		return nil, 200
	}

	session, found := k.GetOrgSession(k.Spec.OrgID)

	if !found {
		// No organisation session has been created, should not be a pre-requisite in site setups, so we pass the request on
		return nil, 200
	}

	// Is it active?
	if session.IsInactive {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
			"key":    k.Spec.OrgID,
		}).Warning("Organisation access is disabled.")

		return errors.New("this organisation access has been disabled, please contact your API administrator"), 403
	}

	// We found a session, apply the quota limiter
	forwardMessage, reason := k.sessionlimiter.ForwardMessage(&session,
		k.Spec.OrgID,
		k.Spec.OrgSessionManager.GetStore(), false, false)

	k.Spec.OrgSessionManager.UpdateSession(k.Spec.OrgID, &session, getLifetime(k.Spec, &session))

	if !forwardMessage {
		if reason == 2 {
			log.WithFields(logrus.Fields{
				"path":   r.URL.Path,
				"origin": GetIPFromRequest(r),
				"key":    k.Spec.OrgID,
			}).Warning("Organisation quota has been exceeded.")

			// Fire a quota exceeded event
			k.FireEvent(EventOrgQuotaExceeded, EventQuotaExceededMeta{
				EventMetaDefault: EventMetaDefault{Message: "Organisation quota has been exceeded", OriginatingRequest: EncodeRequestToEvent(r)},
				Path:             r.URL.Path,
				Origin:           GetIPFromRequest(r),
				Key:              k.Spec.OrgID,
			})

			return errors.New("This organisation quota has been exceeded, please contact your API administrator"), 403
		}
	}

	if config.Monitor.MonitorOrgKeys {
		// Run the trigger monitor
		k.mon.Check(&session, "")
	}

	// Lets keep a reference of the org
	context.Set(r, OrgSessionContext, session)

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

func (k *OrganizationMonitor) ProcessRequestOffThread(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {

	if !config.EnforceOrgQuotas {
		// We aren't enforcing quotas, so skip this altogether
		return nil, 200
	}

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
	if found {
		log.Debug("Is not active")
		if !active {
			return errors.New("This organisation access has been disabled or quota is exceeded, please contact your API administrator"), 403
		}
	}

	log.Debug("Key not found")

	// Request is valid, carry on
	return nil, 200
}

func (k *OrganizationMonitor) AllowAccessNext(orgChan chan bool, r *http.Request) {

	session, found := k.GetOrgSession(k.Spec.OrgID)

	if !found {
		// No organisation session has been created, should not be a pre-requisite in site setups, so we pass the request on
		log.Debug("No session for org, skipping")
		return
	}

	// Is it active?
	if session.IsInactive {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
			"key":    k.Spec.OrgID,
		}).Warning("Organisation access is disabled.")

		//return errors.New("This organisation access has been disabled, please contact your API administrator."), 403
		orgChan <- false
		return
	}

	// We found a session, apply the quota limiter
	isQuotaExceeded := k.sessionlimiter.IsRedisQuotaExceeded(&session, k.Spec.OrgID, k.Spec.OrgSessionManager.GetStore())

	k.Spec.OrgSessionManager.UpdateSession(k.Spec.OrgID, &session, getLifetime(k.Spec, &session))

	if isQuotaExceeded {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
			"key":    k.Spec.OrgID,
		}).Warning("Organisation quota has been exceeded.")

		// Fire a quota exceeded event
		k.FireEvent(EventOrgQuotaExceeded, EventQuotaExceededMeta{
			EventMetaDefault: EventMetaDefault{Message: "Organisation quota has been exceeded", OriginatingRequest: EncodeRequestToEvent(r)},
			Path:             r.URL.Path,
			Origin:           GetIPFromRequest(r),
			Key:              k.Spec.OrgID,
		})

		//return errors.New("This organisation quota has been exceeded, please contact your API administrator"), 403
		orgChan <- false

		if config.Monitor.MonitorOrgKeys {
			// Run the trigger monitor
			k.mon.Check(&session, "")
		}

		return
	}

	if config.Monitor.MonitorOrgKeys {
		// Run the trigger monitor
		k.mon.Check(&session, "")
	}

	// Lets keep a reference of the org
	context.Set(r, OrgSessionContext, session)

	orgChan <- true
}
