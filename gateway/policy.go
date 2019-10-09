package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/rpc"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/user"
)

var _ PolicyLoader = BasePolicyLoader{}

type DBAccessDefinition struct {
	APIName     string            `json:"apiname"`
	APIID       string            `json:"apiid"`
	Versions    []string          `json:"versions"`
	AllowedURLs []user.AccessSpec `bson:"allowed_urls" json:"allowed_urls"` // mapped string MUST be a valid regex
	Limit       *user.APILimit    `json:"limit"`
}

func (d *DBAccessDefinition) ToRegularAD() user.AccessDefinition {
	return user.AccessDefinition{
		APIName:     d.APIName,
		APIID:       d.APIID,
		Versions:    d.Versions,
		AllowedURLs: d.AllowedURLs,
		Limit:       d.Limit,
	}
}

type DBPolicy struct {
	user.Policy
	AccessRights map[string]DBAccessDefinition `bson:"access_rights" json:"access_rights"`
}

func (d *DBPolicy) ToRegularPolicy() user.Policy {
	policy := d.Policy
	policy.AccessRights = make(map[string]user.AccessDefinition)

	for k, v := range d.AccessRights {
		policy.AccessRights[k] = v.ToRegularAD()
	}
	return policy
}

// PolicyLoader is an interface for loading policies into the gateway.
type PolicyLoader interface {
	LoadPolicy(config.Config) (map[string]user.Policy, error)
}

// BasePolicyLoader implements PolicyLoader with the ability to load policies
// from different sources based on configuration settings.
type BasePolicyLoader struct{}

var ErrNoPolicyName = errors.New("No policy record name defined")

func (BasePolicyLoader) LoadPolicy(cfg config.Config) (map[string]user.Policy, error) {
	switch cfg.Policies.PolicySource {
	case "service":
		if cfg.Policies.PolicyConnectionString == "" {
			mainLog.Fatal("No connection string or node ID present. Failing.")
		}
		connStr := config.Global().Policies.PolicyConnectionString
		connStr = connStr + "/system/policies"

		mainLog.Info("Using Policies from Dashboard Service")

		return LoadPoliciesFromDashboard(connStr, cfg.NodeSecret, cfg.Policies.AllowExplicitPolicyID)
	case "rpc":
		return LoadPoliciesFromRPC(config.Global().SlaveOptions.RPCKey)
	default:
		if cfg.Policies.PolicyRecordName == "" {
			return nil, ErrNoPolicyName
		}
		return LoadPoliciesFromFile(config.Global().Policies.PolicyRecordName)
	}
}

func LoadPoliciesFromFile(filePath string) (map[string]user.Policy, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("policy: Couldn't open policy file: %v", err)
	}
	defer f.Close()

	var policies map[string]user.Policy
	if err := json.NewDecoder(f).Decode(&policies); err != nil {
		return nil, fmt.Errorf("policy: Couldn't unmarshal policies: %v", err)
	}
	return policies, nil
}

// LoadPoliciesFromDashboard will connect and download Policies from a Tyk Dashboard instance.
func LoadPoliciesFromDashboard(endpoint, secret string, allowExplicit bool) (map[string]user.Policy, error) {

	// Get the definitions
	newRequest, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to create request: %v", err)
	}

	newRequest.Header.Set("authorization", secret)
	newRequest.Header.Set("x-tyk-nodeid", GetNodeID())

	newRequest.Header.Set("x-tyk-nonce", ServiceNonce)

	log.WithFields(logrus.Fields{
		"prefix": "policy",
	}).Info("Mutex lock acquired... calling")
	c := initialiseClient(10 * time.Second)

	log.WithFields(logrus.Fields{
		"prefix": "policy",
	}).Info("Calling dashboard service for policy list")
	resp, err := c.Do(newRequest)
	if err != nil {
		return nil, fmt.Errorf("Policy request failed:: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		body, _ := ioutil.ReadAll(resp.Body)
		reLogin()
		return nil, fmt.Errorf("Policy request login failure, Response was:: %s", string(body))
	}

	// Extract Policies
	var list struct {
		Message []DBPolicy
		Nonce   string
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("Failed to decode policy body: %v", err)
	}

	ServiceNonce = list.Nonce
	log.Debug("Loading Policies Finished: Nonce Set: ", ServiceNonce)

	policies := make(map[string]user.Policy, len(list.Message))

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

	return policies, nil
}

func parsePoliciesFromRPC(list string) (map[string]user.Policy, error) {
	var dbPolicyList []user.Policy

	if err := json.Unmarshal([]byte(list), &dbPolicyList); err != nil {
		return nil, err
	}

	policies := make(map[string]user.Policy, len(dbPolicyList))

	for _, p := range dbPolicyList {
		p.ID = p.MID.Hex()
		policies[p.MID.Hex()] = p
	}

	return policies, nil
}

func LoadPoliciesFromRPC(orgId string) (map[string]user.Policy, error) {
	if rpc.IsEmergencyMode() {
		return LoadPoliciesFromRPCBackup()
	}

	store := &RPCStorageHandler{}
	if !store.Connect() {
		return nil, errors.New("Policies backup: Failed connecting to database")
	}

	rpcPolicies := store.GetPolicies(orgId)

	policies, err := parsePoliciesFromRPC(rpcPolicies)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "policy",
		}).Error("Failed decode: ", err, rpcPolicies)
		return nil, err
	}

	if err := saveRPCPoliciesBackup(rpcPolicies); err != nil {
		return nil, err
	}

	return policies, nil
}
