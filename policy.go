package main

import (
	"io/ioutil"
	"encoding/json"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
)

type Policy struct {
	MID				 bson.ObjectId 				 `bson:"_id,omitempty" json:"id"`
	ID  			 string 				  	 `bson:"id,omitempty" json:"id"`
	OrgID			 string						 `bson:"org_id" json:"org_id"`
	Rate             float64                     `bson:"rate" json:"rate"`
	Per              float64                     `bson:"per" json:"per"`
	QuotaMax         int64                       `bson:"quota_max" json:"quota_max"`
	QuotaRenewalRate int64                       `bson:"quota_renewal_rate" json:"quota_renewal_rate"`
	AccessRights     map[string]AccessDefinition `bson:"access_rights" json:"access_rights"`
	HMACEnabled      bool        				 `bson:"hmac_enabled" json:"hmac_enabled"`
	Active bool `bson:"active" json:"active"`
	IsInactive bool `bson:"is_inactive" json:"is_inactive"`
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
	
	log.Info("Policies found: ", len(dbPolicyList))
	for _, p := range(dbPolicyList) {
		p.ID = p.MID.Hex()
		policies[p.MID.Hex()] = p
		log.Debug("Processing policy ID: ", p.ID)
	}

	return policies
}