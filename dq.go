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
			// Ignore deleted flags
			if v.Delete {
				log.Warning("Key has been tagged for deletion, not writing counter")
				return
			}

			// We will track all the session handlers for this key
			processedSpecs := map[SessionHandler]struct{}{}

			// Let's go through all the API IDs in the metadata so we capture all the handlers
			for _, aid := range v.Meta.([]interface{}) {
				apiID := aid.(string)

				// This will grab the session handler
				spec := GetSpecForApi(apiID)
				if spec == nil {
					log.Warning("Can't find back-end for this API, skippingc")
					break
				}

				// Have we processed on this handler before (many APIs may use the same handler)?
				_, processedOnSH := processedSpecs[spec.SessionManager]
				if !processedOnSH {
					// This handler hasn't been used yet for the API
					// Get the session data
					s, f := spec.SessionManager.GetSessionDetail(k)

					// If it was found, lets process it for this handler
					if f {
						skip := false
						if s.IsQuotaExpired() {
							QuotaHandler.TagDelete(k)
							skip = true
						}

						if s.IsExpired() {
							// Remove expired data too
							QuotaHandler.TagDelete(k)
							skip = true
						}

						if !skip {
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
						}

					} else {
						// No longer in session store, delete
						QuotaHandler.TagDelete(k)
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

	// We always need a leader because otherwise we can;t persist data
	QuotaHandler.SetLeader(statusFunc())

	// TODO: Must be configurable
	QuotaHandler.FlushInterval = time.Second * 1

	DQFlusherPool.Open()

	if err := QuotaHandler.Start(); err != nil {
		log.Fatal(err)
	}

	// Give us time to catch up
	time.Sleep(time.Millisecond*100)
}

func (l SessionLimiter) IsDistributedQuotaExceeded(currentSession *SessionState, key string) bool {
	// Are they unlimited?
	if currentSession.QuotaMax == -1 {
		// No quota set
		return false
	}

	// Handle renewal
	RenewalDate := time.Unix(currentSession.QuotaRenews, 0)
	if time.Now().After(RenewalDate) {
		// The renewal date is in the past, we should update the quota!
		// Also, this fixes legacy issues where there is no TTL on quota buckets
		log.Warning("Incorrect key expiry setting detected, correcting / or renewing quota")

		// To reset a quota we just delete the ket from our distributed counter, this should propagate
		QuotaHandler.TagDelete(key)

		// Set the new renewal date
		current := time.Now().Unix()
		currentSession.QuotaRenews = current + currentSession.QuotaRenewalRate

		// Reset the quota value:
		currentSession.QuotaRemaining = currentSession.QuotaMax
	}

	// This is cleaner than just copying the access rights
	ar := make([]interface{}, len(currentSession.AccessRights))
	i := 0
	for k := range currentSession.AccessRights {
		ar[i] = k
		i++
	}

	used := int(currentSession.QuotaMax - currentSession.QuotaRemaining)

	QuotaHandler.InitQuota(int(currentSession.QuotaMax),
		used,
		key,
		ar)


	if QuotaHandler.IncrBy(key, 1) == dq.Quota_violated {
		return true
	}

	return false
}
