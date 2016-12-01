package main

import (
	"github.com/gorilla/context"
	"net/http"
	"sync"
)

import (
	"errors"
	"github.com/TykTechnologies/logrus"
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

// New lets you do any initialisations for the object can be done here
func (k *OrganizationMonitor) New() {
	k.sessionlimiter = SessionLimiter{}
	k.mon = Monitor{}
}

func (a *OrganizationMonitor) IsEnabledForSpec() bool {

	if !config.EnforceOrgQuotas {
		// We aren't enforcing quotas, so skip this mw altogether
		return false
	}

	return true
}

// GetConfig retrieves the configuration from the API config - we user mapstructure for this for simplicity
func (k *OrganizationMonitor) GetConfig() (interface{}, error) {
	return nil, nil
}

func (k *OrganizationMonitor) ProcessRequest(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {
	if config.ExperimentalProcessOrgOffThread {
		return k.ProcessRequestOffThread(w, r, configuration)
	} else {
		return k.ProcessRequestLive(w, r, configuration)
	}
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (k *OrganizationMonitor) ProcessRequestLive(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {

	if !config.EnforceOrgQuotas {
		// We aren;t enforcing quotas, so skip this altogether
		return nil, 200
	}

	thisSessionState, found := k.GetOrgSession(k.Spec.OrgID)

	if !found {
		// No organisation session has been created, should not be a pre-requisite in site setups, so we pass the request on
		return nil, 200
	}

	// Is it active?
	if thisSessionState.IsInactive {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
			"key":    k.Spec.OrgID,
		}).Warning("Organisation access is disabled.")

		return errors.New("This organisation access has been disabled, please contact your API administrator."), 403
	}

	// We found a session, apply the quota limiter
	forwardMessage, reason := k.sessionlimiter.ForwardMessage(&thisSessionState,
		k.Spec.OrgID,
		k.Spec.OrgSessionManager.GetStore(), false, false)

	k.Spec.OrgSessionManager.UpdateSession(k.Spec.OrgID, thisSessionState, GetLifetime(k.Spec, &thisSessionState))

	if !forwardMessage {
		if reason == 2 {
			log.WithFields(logrus.Fields{
				"path":   r.URL.Path,
				"origin": GetIPFromRequest(r),
				"key":    k.Spec.OrgID,
			}).Warning("Organisation quota has been exceeded.")

			// Fire a quota exceeded event
			go k.TykMiddleware.FireEvent(EVENT_OrgQuotaExceeded,
				EVENT_QuotaExceededMeta{
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
		k.mon.Check(&thisSessionState, "")
	}

	// Lets keep a reference of the org
	context.Set(r, OrgSessionContext, thisSessionState)

	// Request is valid, carry on
	return nil, 200
}

func (k *OrganizationMonitor) SetOrgSentinel(orgChan chan bool, orgId string) {
	var isActive bool
	for {
		isActive = <-orgChan
		log.Debug("Chan got:", isActive)
		if isActive {
			orgActiveMap.Lock()
			orgActiveMap.OrgMap[orgId] = true
			orgActiveMap.Unlock()
		} else {
			orgActiveMap.Lock()
			orgActiveMap.OrgMap[orgId] = false
			orgActiveMap.Unlock()
		}
	}
}

func (k *OrganizationMonitor) ProcessRequestOffThread(w http.ResponseWriter, r *http.Request, configuration interface{}) (error, int) {

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
			return errors.New("This organisation access has been disabled or quota is exceeded, please contact your API administrator."), 403
		}
	}

	log.Debug("Key not found")

	// Request is valid, carry on
	return nil, 200
}

func (k *OrganizationMonitor) AllowAccessNext(orgChan chan bool, r *http.Request) {

	thisSessionState, found := k.GetOrgSession(k.Spec.OrgID)

	if !found {
		// No organisation session has been created, should not be a pre-requisite in site setups, so we pass the request on
		log.Debug("No session for org, skipping")
		return
	}

	// Is it active?
	if thisSessionState.IsInactive {
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
	isQuotaExceeded := k.sessionlimiter.IsRedisQuotaExceeded(&thisSessionState, k.Spec.OrgID, k.Spec.OrgSessionManager.GetStore())

	k.Spec.OrgSessionManager.UpdateSession(k.Spec.OrgID, thisSessionState, GetLifetime(k.Spec, &thisSessionState))

	if isQuotaExceeded {
		log.WithFields(logrus.Fields{
			"path":   r.URL.Path,
			"origin": GetIPFromRequest(r),
			"key":    k.Spec.OrgID,
		}).Warning("Organisation quota has been exceeded.")

		// Fire a quota exceeded event
		go k.TykMiddleware.FireEvent(EVENT_OrgQuotaExceeded,
			EVENT_QuotaExceededMeta{
				EventMetaDefault: EventMetaDefault{Message: "Organisation quota has been exceeded", OriginatingRequest: EncodeRequestToEvent(r)},
				Path:             r.URL.Path,
				Origin:           GetIPFromRequest(r),
				Key:              k.Spec.OrgID,
			})

		//return errors.New("This organisation quota has been exceeded, please contact your API administrator"), 403
		orgChan <- false

		if config.Monitor.MonitorOrgKeys {
			// Run the trigger monitor
			k.mon.Check(&thisSessionState, "")
		}

		return
	}

	if config.Monitor.MonitorOrgKeys {
		// Run the trigger monitor
		k.mon.Check(&thisSessionState, "")
	}

	// Lets keep a reference of the org
	context.Set(r, OrgSessionContext, thisSessionState)

	orgChan <- true
}
