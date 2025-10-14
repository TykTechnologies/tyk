package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TykTechnologies/tyk/header"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/rpc"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/user"
)

var (
	ErrPoliciesFetchFailed = errors.New("fetch policies request login failure")
)

type DBAccessDefinition struct {
	APIName              string                       `json:"api_name"`
	APIID                string                       `json:"api_id"`
	Versions             []string                     `json:"versions"`
	AllowedURLs          []user.AccessSpec            `bson:"allowed_urls" json:"allowed_urls"` // mapped string MUST be a valid regex
	RestrictedTypes      []graphql.Type               `json:"restricted_types"`
	AllowedTypes         []graphql.Type               `json:"allowed_types"`
	DisableIntrospection bool                         `json:"disable_introspection"`
	FieldAccessRights    []user.FieldAccessDefinition `json:"field_access_rights"`
	Limit                *user.APILimit               `json:"limit"`

	// Endpoints contains endpoint rate limit settings.
	Endpoints user.Endpoints `json:"endpoints,omitempty"`
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
		Endpoints:            d.Endpoints,
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
		log.WithFields(logrus.Fields{
			"prefix": "policy",
		}).Error("Couldn't open policy file: ", err)
		return nil, err
	}
	defer f.Close()

	var policies map[string]user.Policy
	if err := json.NewDecoder(f).Decode(&policies); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "policy",
		}).Error("Couldn't unmarshal policies: ", err)
		return nil, err
	}
	return policies, nil
}

func LoadPoliciesFromDir(dir string) (map[string]user.Policy, error) {
	policies := make(map[string]user.Policy)
	// Grab json files from directory
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		log.Error("error fetch policies path from policies path: ", err)
		return nil, err
	}

	for _, path := range paths {
		log.Info("Loading policy from dir ", path)
		f, err := os.Open(path)
		if err != nil {
			log.Error("Couldn't open policy file from dir: ", err)
			continue
		}
		pol := &user.Policy{}
		if err := json.NewDecoder(f).Decode(pol); err != nil {
			log.Errorf("Couldn't unmarshal policy configuration from dir: %v : %v", path, err)
		}
		f.Close()
		policies[pol.ID] = *pol
	}
	return policies, nil
}

// LoadPoliciesFromDashboard will connect and download Policies from a Tyk Dashboard instance.
func (gw *Gateway) LoadPoliciesFromDashboard(endpoint, secret string) (map[string]user.Policy, error) {
	// Build request function for recovery mechanism
	buildReq := func() (*http.Request, error) {
		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("authorization", secret)
		req.Header.Set(header.XTykNodeID, gw.GetNodeID())
		req.Header.Set(header.XTykSessionID, gw.SessionID)

		gw.ServiceNonceMutex.RLock()
		req.Header.Set(header.XTykNonce, gw.ServiceNonce)
		gw.ServiceNonceMutex.RUnlock()

		return req, nil
	}

	log.WithFields(logrus.Fields{
		"prefix": "policy",
	}).Info("Calling dashboard service for policy list")

	// Execute request with automatic recovery
	resp, err := gw.executeDashboardRequestWithRecovery(buildReq, "policy fetch")
	if err != nil {
		log.Error("Policy request failed: ", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Error("Policy request login failure, Response was: ", string(body))
		return nil, ErrPoliciesFetchFailed
	}

	// Extract Policies
	var list struct {
		Message []DBPolicy
		Nonce   string
	}
	if err = json.NewDecoder(resp.Body).Decode(&list); err != nil {
		log.Error("Failed to decode policy body: ", err)
		// Check if we should retry after a network error during read
		if gw.HandleDashboardResponseReadError(err, "policy fetch") {
			// Retry the entire operation
			return gw.LoadPoliciesFromDashboard(endpoint, secret)
		}
		return nil, err
	}

	gw.ServiceNonceMutex.Lock()
	gw.ServiceNonce = list.Nonce
	gw.ServiceNonceMutex.Unlock()
	log.Debug("Loading Policies Finished: Nonce Set: ", list.Nonce)

	policies := make(map[string]user.Policy, len(list.Message))

	log.WithFields(logrus.Fields{
		"prefix": "policy",
	}).Info("Processing policy list")

	for _, p := range list.Message {
		if !ensurePolicyId(&p.Policy) {
			return nil, fmt.Errorf("invalid policy _id=%q id=%q", p.MID, p.ID)
		}

		if _, ok := policies[p.ID]; ok {
			log.WithFields(logrus.Fields{
				"prefix":   "policy",
				"policyID": p.ID,
				"OrgID":    p.OrgID,
			}).Warning("--> Skipping policy, new item has a duplicate ID!")
			continue
		}

		policies[p.ID] = p.ToRegularPolicy()
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
		if !ensurePolicyId(&p) {
			return nil, fmt.Errorf("invalid policy _id=%q id=%q", p.MID, p.ID)
		}
		policies[p.ID] = p
	}

	return policies, nil
}

func (gw *Gateway) LoadPoliciesFromRPC(store RPCDataLoader, orgId string) (map[string]user.Policy, error) {
	if rpc.IsEmergencyMode() {
		return gw.LoadPoliciesFromRPCBackup()
	}

	if !store.Connect() {
		return nil, errors.New("Policies backup: Failed connecting to database")
	}

	rpcPolicies := store.GetPolicies(orgId)
	if rpcPolicies == "" {
		return nil, errors.New("failed to fetch policies from RPC store; connection may be down")
	}

	policies, err := parsePoliciesFromRPC(rpcPolicies)

	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "policy",
		}).Error("Failed decode: ", err, rpcPolicies)
		return nil, err
	}

	if err := gw.saveRPCPoliciesBackup(rpcPolicies); err != nil {
		log.Error(err)
	}

	return policies, nil
}

// ensurePolicyId ensures ID field exists
// should be removed after migrate
func ensurePolicyId(policy *user.Policy) bool {
	if policy == nil {
		return false
	}

	if policy.ID != "" {
		return true
	}

	if !policy.MID.Valid() {
		return false
	}

	policy.ID = policy.MID.Hex()
	return true
}
