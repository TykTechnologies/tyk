package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"gopkg.in/mgo.v2/bson"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/config"
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
	return AccessDefinition{
		APIName:     d.APIName,
		APIID:       d.APIID,
		Versions:    d.Versions,
		AllowedURLs: d.AllowedURLs,
	}
}

type DBPolicy struct {
	Policy
	AccessRights map[string]DBAccessDefinition `bson:"access_rights" json:"access_rights"`
}

func (d *DBPolicy) ToRegularPolicy() Policy {
	policy := d.Policy
	policy.AccessRights = make(map[string]AccessDefinition)

	for k, v := range d.AccessRights {
		policy.AccessRights[k] = v.ToRegularAD()
	}
	return policy
}

func LoadPoliciesFromFile(filePath string) map[string]Policy {
	f, err := os.Open(filePath)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "policy",
		}).Error("Couldn't open policy file: ", err)
		return nil
	}
	defer f.Close()

	var policies map[string]Policy
	if err := json.NewDecoder(f).Decode(&policies); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "policy",
		}).Error("Couldn't unmarshal policies: ", err)
	}
	return policies
}

// LoadPoliciesFromDashboard will connect and download Policies from a Tyk Dashboard instance.
func LoadPoliciesFromDashboard(endpoint, secret string, allowExplicit bool) map[string]Policy {

	// Get the definitions
	newRequest, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Error("Failed to create request: ", err)
	}

	newRequest.Header.Set("authorization", secret)
	newRequest.Header.Set("x-tyk-nodeid", NodeID)

	newRequest.Header.Set("x-tyk-nonce", ServiceNonce)

	log.WithFields(logrus.Fields{
		"prefix": "policy",
	}).Info("Mutex lock acquired... calling")
	c := &http.Client{
		Timeout: 10 * time.Second,
	}

	log.WithFields(logrus.Fields{
		"prefix": "policy",
	}).Info("Calling dashboard service for policy list")
	resp, err := c.Do(newRequest)
	if err != nil {
		log.Error("Policy request failed: ", err)
		return nil
	}
	defer resp.Body.Close()

	// Extract Policies
	type NodeResponseOK struct {
		Status  string
		Message []DBPolicy
		Nonce   string
	}

	if resp.StatusCode == 403 {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Error("Policy request login failure, Response was: ", string(body))
		reLogin()
		return nil
	}

	list := NodeResponseOK{}

	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		log.Error("Failed to decode policy body: ", err)
		return nil
	}

	ServiceNonce = list.Nonce
	log.Debug("Loading Policies Finished: Nonce Set: ", ServiceNonce)

	policies := make(map[string]Policy, len(list.Message))

	log.WithFields(logrus.Fields{
		"prefix": "policy",
	}).Info("Processing policy list")
	for _, p := range list.Message {
		id := p.MID.Hex()
		if allowExplicit && p.ID != "" {
			id = p.ID
		}
		p.ID = id
		if _, ok := policies[id]; ok {
			log.WithFields(logrus.Fields{
				"prefix":   "policy",
				"policyID": p.ID,
				"OrgID":    p.OrgID,
			}).Warning("--> Skipping policy, new item has a duplicate ID!")
			continue
		}
		policies[id] = p.ToRegularPolicy()
	}

	return policies
}

func LoadPoliciesFromRPC(orgId string) map[string]Policy {
	var dbPolicyList []Policy

	store := &RPCStorageHandler{UserKey: config.Global.SlaveOptions.APIKey, Address: config.Global.SlaveOptions.ConnectionString}
	store.Connect()

	rpcPolicies := store.GetPolicies(orgId)

	//store.Disconnect()

	if err := json.Unmarshal([]byte(rpcPolicies), &dbPolicyList); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "policy",
		}).Error("Failed decode: ", err)
		return nil
	}

	policies := make(map[string]Policy, len(dbPolicyList))

	for _, p := range dbPolicyList {
		p.ID = p.MID.Hex()
		policies[p.MID.Hex()] = p
	}

	return policies
}
