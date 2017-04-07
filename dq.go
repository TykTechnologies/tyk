package main

import (
	"fmt"
	"github.com/TykTechnologies/tyk-cluster-framework/client"
	"github.com/TykTechnologies/tyk-cluster-framework/encoding"
	"strconv"
	"strings"
	"time"

	"github.com/TykTechnologies/dq"
	"github.com/TykTechnologies/logrus"
	"github.com/TykTechnologies/tykcommon"
	"github.com/jeffail/tunny"
)

var DQFlusherPool *tunny.WorkPool = tunny.CreatePoolGeneric(10)
var QuotaHandler *dq.DistributedQuota

type GetLeaderStatusFunc func() bool

func GetLeaderStatusFromConf() bool {
	return config.SetAsLeader
}

func getDQTopic() string {
	topic := "tyk.dq"
	if config.DBAppConfOptions.NodeIsSegmented {
		if len(config.DBAppConfOptions.Tags) > 0 {
			tags := strings.Join(config.DBAppConfOptions.Tags, ".")
			topic = topic + "." + tags
		}
	}

	return topic
}

func DQErrorHandler(e error) {
	log.WithFields(logrus.Fields{
		"prefix": "main.DQ",
	}).Error(e)
}

var dummyAPISpec APISpec = APISpec{APIDefinition: &tykcommon.APIDefinition{SessionLifetime: 0}}

func DQFlusher(d map[string]*dq.Quota) error {
	for k, v := range d {
		DQFlusherPool.SendWork(func() {
			// We will track all the session handlers for this key
			processedSpecs := map[SessionHandler]struct{}{}

			// Let's go through all the API IDs in the metadata so we capture all the handlers
			for apiID, _ := range v.Meta.(map[string]AccessDefinition) {
				// This will grab the session handler
				spec := GetSpecForApi(apiID)

				// Have we processed on this handler before (many APIs may use the same handler)?
				_, processedOnSH := processedSpecs[spec.SessionManager]
				if !processedOnSH {
					// This handler hasn't been used yet for the API
					// Get the session data
					s, f := spec.SessionManager.GetSessionDetail(k)

					// If it was found, lets process it for this handler
					if f {
						qr := int64(v.Max - v.Counter.Count())
						if qr < 0 {
							qr = 0
						}

						// Only write on count difference
						if qr != s.QuotaRemaining {
							s.QuotaRemaining = qr

							spec.SessionManager.UpdateSession(k, s, GetLifetime(&dummyAPISpec, &s))
							log.Debug("Updating quota for: ", k)
							// We've performed a write on this SH now, lets tag that so we don't do it again
							processedSpecs[spec.SessionManager] = struct{}{}
						}

						if s.IsExpired() {
							// Remove expired data too
							QuotaHandler.Delete(k)
						}
					} else {
						// No longer in session store, delete
						QuotaHandler.Delete(k)
					}
				}
			}
		})
	}

	return nil

}

func StartDQ(statusFunc GetLeaderStatusFunc) {
	p := strconv.Itoa(config.Storage.Port)
	cs := fmt.Sprintf("redis://%v:%v", config.Storage.Host, p)
	c1, _ := client.NewClient(cs, encoding.JSON)

	QuotaHandler = dq.NewDQ(DQFlusher, DQErrorHandler, NodeID)
	QuotaHandler.BroadcastWith(c1, time.Millisecond*100, getDQTopic())

	// TODO: Leader must be decided in a sane way
	QuotaHandler.SetLeader(statusFunc())

	// TODO: Must be configurable
	QuotaHandler.FlushInterval = time.Second * 1

	DQFlusherPool.Open()

	if err := QuotaHandler.Start(); err != nil {
		log.Fatal(err)
	}
}

func (l SessionLimiter) IsDistributedQuotaExceeded(currentSession *SessionState, key string) bool {
	QuotaHandler.InitQuota(int(currentSession.QuotaMax),
		int(currentSession.QuotaMax-currentSession.QuotaRemaining),
		key, currentSession.AccessRights)

	// TODO: Handle renewal
	if QuotaHandler.IncrBy(key, 1) == dq.Quota_violated {
		return true
	}

	return false
}
