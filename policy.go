package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/TykTechnologies/logrus"
	"gopkg.in/mgo.v2/bson"
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
	Partitions       struct {
		Quota     bool `bson:"quota" json:"quota"`
		RateLimit bool `bson:"rate_limit" json:"rate_limit"`
		Acl       bool `bson:"acl" json:"acl"`
	} `bson:"partitions" json:"partitions"`
	LastUpdated string `bson:"last_updated" json:"last_updated"`
}

type DBAccessDefinition struct {
	APIName     string       `json:"apiname"`
	APIID       string       `json:"apiid"`
	Versions    []string     `json:"versions"`
	AllowedURLs []AccessSpec `bson:"allowed_urls"  json:"allowed_urls"` // mapped string MUST be a valid regex
}

func (d *DBAccessDefinition) ToRegularAD() AccessDefinition {
	thisAD := AccessDefinition{
		APIName:     d.APIName,
		APIID:       d.APIID,
		Versions:    d.Versions,
		AllowedURLs: d.AllowedURLs,
	}

	return thisAD
}

type DBPolicy struct {
	Policy
	AccessRights map[string]DBAccessDefinition `bson:"access_rights" json:"access_rights"`
}

func (d *DBPolicy) ToRegularPolicy() Policy {
	thisPolicy := Policy(d.Policy)
	thisPolicy.AccessRights = make(map[string]AccessDefinition)

	for k, v := range d.AccessRights {
		thisPolicy.AccessRights[k] = v.ToRegularAD()
	}

	return thisPolicy
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
func LoadPoliciesFromDashboard(endpoint string, secret string, allowExplicit bool) map[string]Policy {

	policies := make(map[string]Policy)

	// Get the definitions
	newRequest, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Error("Failed to create request: ", err)
	}

	newRequest.Header.Add("authorization", secret)
	newRequest.Header.Add("x-tyk-nodeid", NodeID)

	newRequest.Header.Add("x-tyk-nonce", ServiceNonce)

	log.WithFields(logrus.Fields{
		"prefix": "policy",
	}).Info("Mutex lock acquired... calling")
	c := &http.Client{
		Timeout: 10 * time.Second,
	}

	log.WithFields(logrus.Fields{
		"prefix": "policy",
	}).Info("Calling dashboard service for policy list")
	response, reqErr := c.Do(newRequest)

	if reqErr != nil {
		log.Error("Policy request failed: ", reqErr)

		return policies
	}

	defer response.Body.Close()
	retBody, err := ioutil.ReadAll(response.Body)

	if err != nil {
		log.Error("Failed to read policy body: ", err)

		return policies
	}

	// Extract Policies
	type NodeResponseOK struct {
		Status  string
		Message []DBPolicy
		Nonce   string
	}

	if response.StatusCode == 403 {
		log.Error("Policy request login failure, Response was: ", string(retBody))
		reloadScheduled = false

		ReLogin()
		return policies
	}

	thisList := NodeResponseOK{}

	decErr := json.Unmarshal(retBody, &thisList)
	if decErr != nil {
		log.Error("Failed to decode policy body: ", decErr, "Returned: ", string(retBody))

		return policies
	}

	ServiceNonce = thisList.Nonce
	log.Debug("Loading Policies Finished: Nonce Set: ", ServiceNonce)

	log.WithFields(logrus.Fields{
		"prefix": "policy",
	}).Info("Processing policy list")
	for _, p := range thisList.Message {
		thisID := p.MID.Hex()
		if allowExplicit {
			if p.ID != "" {
				thisID = p.ID
			}
		}
		p.ID = thisID
		_, foundP := policies[thisID]
		if !foundP {
			policies[thisID] = p.ToRegularPolicy()
			log.WithFields(logrus.Fields{
				"prefix": "policy",
			}).Info("--> Processing policy ID: ", p.ID)
			log.Debug("POLICY ACCESS RIGHTS: ", p.AccessRights)
		} else {
			log.WithFields(logrus.Fields{
				"prefix":   "policy",
				"policyID": p.ID,
				"OrgID":    p.OrgID,
			}).Warning("--> Skipping policy, new item has a duplicate ID!")
		}
	}

	return policies
}

func LoadPoliciesFromRPC(orgId string) map[string]Policy {
	dbPolicyList := make([]Policy, 0)
	policies := make(map[string]Policy)

	store := &RPCStorageHandler{UserKey: config.SlaveOptions.APIKey, Address: config.SlaveOptions.ConnectionString}
	store.Connect()

	rpcPolicies := store.GetPolicies(orgId)

	//store.Disconnect()

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
