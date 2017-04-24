package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk-cluster-framework/client"
	"github.com/TykTechnologies/tyk-cluster-framework/encoding"

	"github.com/jeffail/tunny"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/dq"
	"github.com/TykTechnologies/tyk/apidef"
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

func dqErrorHandler(e error) {
	log.WithFields(logrus.Fields{
		"prefix": "main.DQ",
	}).Error(e)
}

var dummyAPISpec = APISpec{APIDefinition: &apidef.APIDefinition{SessionLifetime: 0}}

func dqFlusher(d map[string]*dq.Quota) error {
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
			apis := v.Meta.(map[string]interface{})["Apis"]

			// I hate this
			var exp int64
			switch x := v.Meta.(map[string]interface{})["QuotaRenewal"].(type) {
			case int64:
				exp = x
			case float64:
				exp = int64(x)
			}

			expT := time.Unix(exp, 0)
			for _, aid := range apis.([]interface{}) {
				apiID := aid.(string)

				// This will grab the session handler
				spec := GetSpecForApi(apiID)
				if spec == nil {
					log.Warning("Can't find back-end for this API, skippingc")
					break
				}

				// Have we processed on this handler before (many APIs may use the same handler)?
				_, processedOnSH := processedSpecs[spec.SessionManager]
				if processedOnSH {
					continue
				}

				// This handler hasn't been used yet for the API
				// Get the session data
				s, f := spec.SessionManager.GetSessionDetail(k)

				// If it was found, lets process it for this handler
				if !f {
					// No longer in session store, delete
					QuotaHandler.TagDelete(k)
					continue
				}

				skip := false
				if time.Now().After(expT) {
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
						// Since we've written the token, we don't need to re-do it at the end of the middleware chain
						s.SetFirstSeenHash()
						// We've performed a write on this SH now, lets tag that so we don't do it again
						processedSpecs[spec.SessionManager] = struct{}{}
					}
				}

			}
		})
	}

	return nil

}

func startDQ(statusFunc GetLeaderStatusFunc) {
	log.WithFields(logrus.Fields{
		"prefix": "DQuota",
	}).Info("Using Distributed Quota")
	p := strconv.Itoa(config.Storage.Port)
	cs := fmt.Sprintf("redis://%v:%v", config.Storage.Host, p)
	c1, _ := client.NewClient(cs, encoding.JSON)

	QuotaHandler = dq.NewDQ(dqFlusher, dqErrorHandler, NodeID)
	QuotaHandler.BroadcastWith(c1, time.Millisecond*100, getDQTopic())

	// We always need a leader because otherwise we can;t persist data
	QuotaHandler.SetLeader(statusFunc())

	QuotaHandler.FlushInterval = time.Second * 3
	if config.DistributedQuotaFlushIntervalInMS != 0 {
		QuotaHandler.FlushInterval = time.Millisecond * time.Duration(config.DistributedQuotaFlushIntervalInMS)
	}

	DQFlusherPool.Open()

	if err := QuotaHandler.Start(); err != nil {
		log.Fatal(err)
	}

	// Give us time to catch up
	time.Sleep(time.Millisecond * 100)
}

func (l SessionLimiter) IsDistributedQuotaExceeded(currentSession *SessionState, key string) bool {

	// Are they unlimited?
	if currentSession.QuotaMax == -1 {
		// No quota set
		return false
	}

	// store the old expiry so we propagate the right value
	md := map[string]interface{}{
		"QuotaRenewal": currentSession.QuotaRenews,
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

	md["Apis"] = ar

	used := int(currentSession.QuotaMax - currentSession.QuotaRemaining)

	QuotaHandler.InitQuota(int(currentSession.QuotaMax),
		used,
		key,
		md)

	return QuotaHandler.IncrBy(key, 1) == dq.Quota_violated
}
