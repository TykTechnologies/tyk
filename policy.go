package main

import (
	"encoding/json"
	"github.com/Sirupsen/logrus"
	"gopkg.in/mgo.v2/bson"
	"io/ioutil"
	"net/http"
)

type Policy struct {
	MID              bson.ObjectId               `bson:"_id,omitempty" json:"_id"`
	ID               string                      `bson:"id,omitempty" json:"id"`
	OrgID            string                      `bson:"org_id" json:"org_id"`
	Rate             float64                     `bson:"rate" json:"rate"`
	Per              float64                     `bson:"per" json:"per"`
	QuotaMax         int64                       `bson:"quota_max" json:"quota_max"`
	QuotaRenewalRate int64                       `bson:"quota_renewal_rate" json:"quota_renewal_rate"`
	AccessRights     map[string]AccessDefinition `bson:"access_rights" json:"access_rights"`
	HMACEnabled      bool                        `bson:"hmac_enabled" json:"hmac_enabled"`
	Active           bool                        `bson:"active" json:"active"`
	IsInactive       bool                        `bson:"is_inactive" json:"is_inactive"`
	Tags             []string                    `bson:"tags" json:"tags"`
	KeyExpiresIn     int64                       `bson:"key_expires_in" json:"key_expires_in"`
}

func LoadPoliciesFromFile(filePath string) map[string]Policy {
	policies := make(map[string]Policy)

	policyConfig, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "policy",
		}).Error("Couldn't load policy file: ", err)
		return policies
	}

	mErr := json.Unmarshal(policyConfig, &policies)
	if mErr != nil {
		log.WithFields(logrus.Fields{
			"prefix": "policy",
		}).Error("Couldn't unmarshal policies: ", mErr)
	}

	return policies
}

// LoadPoliciesFromDashboard will connect and download Policies from a Tyk Dashboard instance.
func LoadPoliciesFromDashboard(endpoint string, secret string) map[string]Policy {

	policies := make(map[string]Policy)

	// Get the definitions
	log.Debug("Calling: ", endpoint)
	newRequest, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Error("Failed to create request: ", err)
	}

	newRequest.Header.Add("authorization", secret)
	newRequest.Header.Add("x-tyk-nodeid", NodeID)

	ServiceNonceMutex.Lock()
	newRequest.Header.Add("x-tyk-nonce", ServiceNonce)
	ServiceNonceMutex.Unlock()

	c := &http.Client{}
	response, reqErr := c.Do(newRequest)

	if reqErr != nil {
		log.Error("Request failed: ", reqErr)
		return policies
	}

	defer response.Body.Close()
	retBody, err := ioutil.ReadAll(response.Body)

	if err != nil {
		log.Error("Failed to read body: ", err)
		return policies
	}

	// Extract Policies
	type NodeResponseOK struct {
		Status  string
		Message []Policy
		Nonce   string
	}

	thisList := NodeResponseOK{}

	decErr := json.Unmarshal(retBody, &thisList)
	if decErr != nil {
		log.Error("Failed to decode body: ", decErr)
		return policies
	}

	ServiceNonceMutex.Lock()
	ServiceNonce = thisList.Nonce
	log.Debug("Loading Policies Finished: Nonce Set: ", ServiceNonce)
	ServiceNonceMutex.Unlock()

	for _, p := range thisList.Message {
		p.ID = p.MID.Hex()
		policies[p.MID.Hex()] = p
		log.WithFields(logrus.Fields{
			"prefix": "policy",
		}).Info("--> Processing policy ID: ", p.ID)
	}

	return policies
}

func LoadPoliciesFromRPC(orgId string) map[string]Policy {
	dbPolicyList := make([]Policy, 0)
	policies := make(map[string]Policy)

	store := &RPCStorageHandler{UserKey: config.SlaveOptions.APIKey, Address: config.SlaveOptions.ConnectionString}
	store.Connect()

	rpcPolicies := store.GetPolicies(orgId)

	store.Disconnect()

	jErr1 := json.Unmarshal([]byte(rpcPolicies), &dbPolicyList)

	if jErr1 != nil {
		log.WithFields(logrus.Fields{
			"prefix": "policy",
		}).Error("Failed decode: ", jErr1)
		return policies
	}

	log.WithFields(logrus.Fields{
		"prefix": "policy",
	}).Info("Policies found: ", len(dbPolicyList))
	for _, p := range dbPolicyList {
		p.ID = p.MID.Hex()
		policies[p.MID.Hex()] = p
		log.WithFields(logrus.Fields{
			"prefix": "policy",
		}).Info("--> Processing policy ID: ", p.ID)
	}

	return policies
}
