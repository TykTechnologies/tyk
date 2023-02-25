package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"
	"github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/user"
)

type DBAccessDefinition struct {
	APIName              string                       `json:"apiname"`
	APIID                string                       `json:"apiid"`
	Versions             []string                     `json:"versions"`
	AllowedURLs          []user.AccessSpec            `bson:"allowed_urls" json:"allowed_urls"` // mapped string MUST be a valid regex
	RestrictedTypes      []graphql.Type               `json:"restricted_types"`
	AllowedTypes         []graphql.Type               `json:"allowed_types"`
	DisableIntrospection bool                         `json:"disable_introspection"`
	FieldAccessRights    []user.FieldAccessDefinition `json:"field_access_rights"`
	Limit                *user.APILimit               `json:"limit"`
}

func (d *DBAccessDefinition) ToRegularAD() user.AccessDefinition {
	ad := user.AccessDefinition{
		APIName:              d.APIName,
		APIID:                d.APIID,
		Versions:             d.Versions,
		AllowedURLs:          d.AllowedURLs,
		RestrictedTypes:      d.RestrictedTypes,
		AllowedTypes:         d.AllowedTypes,
		DisableIntrospection: d.DisableIntrospection,
		FieldAccessRights:    d.FieldAccessRights,
	}

	if d.Limit != nil {
		ad.Limit = *d.Limit
	}
	return ad
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

func LoadPoliciesFromFile(filePath string) (map[string]user.Policy, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var policies map[string]user.Policy
	if err := json.NewDecoder(f).Decode(&policies); err != nil {
		return nil, err
	}
	return policies, nil
}

func LoadPoliciesFromDir(dir string) map[string]user.Policy {
	policies := make(map[string]user.Policy)
	// Grab json files from directory
	paths, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, path := range paths {
		policyLog.Info("Loading policy from dir ", path)
		f, err := os.Open(path)
		if err != nil {
			policyLog.Error("Couldn't open policy file from dir: ", err)
			continue
		}
		pol := &user.Policy{}
		if err := json.NewDecoder(f).Decode(pol); err != nil {
			policyLog.Errorf("Couldn't unmarshal policy configuration from dir: %v : %v", path, err)
		}
		f.Close()
		policies[pol.ID] = *pol
	}
	return policies
}

// LoadPoliciesFromDashboard will connect and download Policies from a Tyk Dashboard instance.
func (gw *Gateway) LoadPoliciesFromDashboard(endpoint, secret string, allowExplicit bool) (map[string]user.Policy, error) {

	// Get the definitions
	newRequest, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	newRequest.Header.Set("authorization", secret)
	newRequest.Header.Set("x-tyk-nodeid", gw.GetNodeID())

	gw.ServiceNonceMutex.RLock()
	newRequest.Header.Set("x-tyk-nonce", gw.ServiceNonce)
	gw.ServiceNonceMutex.RUnlock()

	policyLog.WithFields(log.Fields{
		"prefix": "policy",
	}).Info("Mutex lock acquired... calling")
	c := gw.initialiseClient()

	policyLog.WithFields(log.Fields{
		"prefix": "policy",
	}).Info("Calling dashboard service for policy list")
	resp, err := c.Do(newRequest)
	if err != nil {
		policyLog.Error("Policy request failed: ", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		policyLog.WithField("response", string(body)).Error("Policy request login failure")
		gw.reLogin()
		return nil, err
	}

	// Extract Policies
	var list struct {
		Message []DBPolicy
		Nonce   string
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		policyLog.Error("Failed to decode policy body: ", err)
		return nil, err
	}

	gw.ServiceNonceMutex.Lock()
	gw.ServiceNonce = list.Nonce
	gw.ServiceNonceMutex.Unlock()
	policyLog.Debug("Loading Policies Finished: Nonce Set: ", list.Nonce)

	policies := make(map[string]user.Policy, len(list.Message))

	policyLog.Info("Processing policy list")
	for _, p := range list.Message {
		id := p.MID.Hex()
		if allowExplicit && p.ID != "" {
			id = p.ID
		}
		p.ID = id
		if _, ok := policies[id]; ok {
			policyLog.WithFields(log.Fields{
				"policyID": p.ID,
				"OrgID":    p.OrgID,
			}).Warning("--> Skipping policy, new item has a duplicate ID!")
			continue
		}
		policies[id] = p.ToRegularPolicy()
	}

	return policies, nil
}

func parsePoliciesFromRPC(list string, allowExplicit bool) (map[string]user.Policy, error) {
	var dbPolicyList []user.Policy

	if err := json.Unmarshal([]byte(list), &dbPolicyList); err != nil {
		return nil, err
	}

	policies := make(map[string]user.Policy, len(dbPolicyList))

	for _, p := range dbPolicyList {
		id := p.MID.Hex()
		if allowExplicit && p.ID != "" {
			id = p.ID
		}
		p.ID = id
		policies[id] = p
	}

	return policies, nil
}

func (gw *Gateway) LoadPoliciesFromRPC(orgId string, allowExplicit bool) (map[string]user.Policy, error) {
	if rpc.IsEmergencyMode() {
		return gw.LoadPoliciesFromRPCBackup()
	}

	store := &RPCStorageHandler{Gw: gw}
	if !store.Connect() {
		return nil, errors.New("Policies backup: Failed connecting to database")
	}

	rpcPolicies := store.GetPolicies(orgId)

	policies, err := parsePoliciesFromRPC(rpcPolicies, allowExplicit)

	if err != nil {
		return nil, err
	}

	if err := gw.saveRPCPoliciesBackup(rpcPolicies); err != nil {
		policyLog.WithError(err).Error("error saving policies backup")
	}

	return policies, nil
}
