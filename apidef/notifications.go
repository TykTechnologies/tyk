package apidef

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	logger "github.com/TykTechnologies/tyk/log"
)

var log = logger.Get()
var httpClient = initHttpNotificationClient()

// NotificationsManager handles sending notifications to OAuth endpoints to notify the provider of key changes.
// TODO: Make this more generic
type NotificationsManager struct {
	SharedSecret      string `bson:"shared_secret" json:"shared_secret"`
	OAuthKeyChangeURL string `bson:"oauth_on_keychange_url" json:"oauth_on_keychange_url"`
}

func initHttpNotificationClient() *http.Client {
	var netTransport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &http.Client{
		Timeout:   time.Second * 10,
		Transport: netTransport,
	}

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

	postBody, errMarshaling := json.Marshal(notification)
	if errMarshaling != nil {
		log.Error("Error Marshaling the notification body.")
		return
	}
	responseBody := bytes.NewBuffer(postBody)

	req, err := http.NewRequest("POST", n.OAuthKeyChangeURL, responseBody)
	if err != nil {
		log.Fatalln(err)
	}
	req.Header.Set("User-Agent", "Tyk-Gatewy-Notifications")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tyk-Shared-Secret", n.SharedSecret)

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Error("Request failed, trying again in 10s. Error was: ", err)
		count++
		n.SendRequest(true, count, notification)
		return
	}
	defer resp.Body.Close()
	_, errRead := ioutil.ReadAll(resp.Body)
	if errRead != nil {
		log.Error("Request failed, trying again in 10s. Error was: ", err)
		count++
		n.SendRequest(true, count, notification)
		return
	}

	if resp.StatusCode != 200 {
		log.Error("Request returned non-200 status, trying again in 10s.")
		count++
		n.SendRequest(true, count, notification)
		return
	}
}
