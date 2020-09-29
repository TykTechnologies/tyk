package apidef

import (
	"time"

	logger "github.com/TykTechnologies/tyk/v3/log"

	"github.com/franela/goreq"
)

var log = logger.Get()

// NotificationsManager handles sending notifications to OAuth endpoints to notify the provider of key changes.
// TODO: Make this more generic
type NotificationsManager struct {
	SharedSecret      string `bson:"shared_secret" json:"shared_secret"`
	OAuthKeyChangeURL string `bson:"oauth_on_keychange_url" json:"oauth_on_keychange_url"`
}

// SendRequest sends the requested package (as a POST) to the defined
func (n NotificationsManager) SendRequest(wait bool, count int, notification interface{}) {
	if n.OAuthKeyChangeURL == "" {
		return
	}

	if wait {
		if count < 3 {
			time.Sleep(10 * time.Second)
		} else {
			log.Error("Too many notification attempts, aborting.")
			return
		}
	}

	req := goreq.Request{
		Method:      "POST",
		Uri:         n.OAuthKeyChangeURL,
		UserAgent:   "Tyk-Gatewy-Notifications",
		ContentType: "application/json",
		Body:        notification,
	}

	req.AddHeader("X-Tyk-Shared-Secret", n.SharedSecret)

	resp, err := req.Do()
	if err != nil {
		log.Error("Request failed, trying again in 10s. Error was: ", err)
		count++
		go n.SendRequest(true, count, notification)
		return
	}
	if resp.StatusCode != 200 {
		log.Error("Request returned non-200 status, trying again in 10s.")
		count++
		go n.SendRequest(true, count, notification)
		return
	}
}
