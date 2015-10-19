package main

import (
	"encoding/json"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"io/ioutil"
	"time"
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
		log.Error("Couldn't load policy file: ", err)
		return policies
	}

	mErr := json.Unmarshal(policyConfig, &policies)
	if mErr != nil {
		log.Error("Couldn't unmarshal policies: ", mErr)
	}

	return policies
}

// LoadPoliciesFromMongo will connect and download POlicies from a Mongo DB instance.
func LoadPoliciesFromMongo(collectionName string) map[string]Policy {
	dbPolicyList := make([]Policy, 0)
	policies := make(map[string]Policy)

	dbSession, dErr := mgo.Dial(config.AnalyticsConfig.MongoURL)
	if dErr != nil {
		log.Error("Mongo connection failed:", dErr)
		time.Sleep(5)
		return LoadPoliciesFromMongo(collectionName)
	}

	log.Debug("Searching in collection: ", collectionName)
	policyCollection := dbSession.DB("").C(collectionName)

	search := bson.M{
		"active": true,
	}

	mongoErr := policyCollection.Find(search).All(&dbPolicyList)

	if mongoErr != nil {
		log.Error("Could not find any policy configs! ", mongoErr)
		return policies
	}

	log.Printf("Loaded %v policies ", len(dbPolicyList))
	for _, p := range dbPolicyList {
		p.ID = p.MID.Hex()
		policies[p.MID.Hex()] = p
		log.Info("--> Processing policy ID: ", p.ID)
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
		log.Error("Failed decode: ", jErr1)
		return policies
	}

	log.Info("Policies found: ", len(dbPolicyList))
	for _, p := range dbPolicyList {
		p.ID = p.MID.Hex()
		policies[p.MID.Hex()] = p
		log.Info("--> Processing policy ID: ", p.ID)
	}

	return policies
}
