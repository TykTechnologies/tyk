package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/TykTechnologies/tyk/header"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

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
func (gw *Gateway) LoadPoliciesFromDashboard(endpoint, secret string, allowExplicit bool) (map[string]user.Policy, error) {

	// Get the definitions
	newRequest, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Error("Failed to create request: ", err)
		return nil, err
	}

	newRequest.Header.Set("authorization", secret)
	newRequest.Header.Set(header.XTykNodeID, gw.GetNodeID())
	newRequest.Header.Set(header.XTykSessionID, gw.SessionID)

	gw.ServiceNonceMutex.RLock()
	newRequest.Header.Set("x-tyk-nonce", gw.ServiceNonce)
	gw.ServiceNonceMutex.RUnlock()

	log.WithFields(logrus.Fields{
		"prefix": "policy",
	}).Info("Mutex lock acquired... calling")
	c := gw.initialiseClient()

	log.WithFields(logrus.Fields{
		"prefix": "policy",
	}).Info("Calling dashboard service for policy list")
	resp, err := c.Do(newRequest)
	if err != nil {
		log.Error("Policy request failed: ", err)
		// Check if this might be a transient network error that could benefit from re-registration
		// This handles load balancer draining scenarios where connections are dropped
		if gw.DashService != nil {
			log.Warning("Network error detected during policy fetch, attempting to re-register node...")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			
			if regErr := gw.DashService.Register(ctx); regErr != nil {
				log.Error("Failed to re-register node after network error: ", regErr)
				return nil, err // Return original error
			}
			log.Info("Node re-registered successfully after network error, retrying policy fetch...")
			
			// Retry the request with fresh registration
			return gw.LoadPoliciesFromDashboard(endpoint, secret, allowExplicit)
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		errorMessage := string(body)
		log.Error("Policy request login failure, Response was: ", errorMessage)

		// Handle nonce desynchronization with intelligent auto-recovery
		if resp.StatusCode == http.StatusForbidden {
			// Only attempt recovery for nonce-related failures, not other auth failures
			if strings.Contains(errorMessage, "Nonce failed") || strings.Contains(errorMessage, "nonce") || strings.Contains(errorMessage, "No node ID Found") {
				log.Warning("Dashboard nonce failure detected, attempting to re-register node...")
				
				// Check if DashService is available for recovery
				if gw.DashService == nil {
					log.Error("Dashboard service not available for nonce recovery")
					return nil, ErrPoliciesFetchFailed
				}
				
				// Use a timeout context to prevent hanging in tests
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				
				if err := gw.DashService.Register(ctx); err != nil {
					log.Error("Failed to re-register node during policy recovery: ", err)
					return nil, ErrPoliciesFetchFailed
				}
				log.Info("Node re-registered successfully, retrying policy fetch...")
				
				// Retry the request with the new nonce
				return gw.LoadPoliciesFromDashboard(endpoint, secret, allowExplicit)
			} else {
				log.Warning("Dashboard authentication failed with non-nonce error: ", errorMessage)
			}
		}

		return nil, ErrPoliciesFetchFailed
	}

	// Extract Policies
	var list struct {
		Message []DBPolicy
		Nonce   string
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		log.Error("Failed to decode policy body: ", err)
		// Check if this is a network error (EOF, unexpected EOF) that might benefit from re-registration
		// This can happen when load balancer drains connection during response body read
		if (err == io.EOF || err == io.ErrUnexpectedEOF || strings.Contains(err.Error(), "EOF")) && gw.DashService != nil {
			log.Warning("Network error detected while reading policy response, attempting to re-register node...")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			
			if regErr := gw.DashService.Register(ctx); regErr != nil {
				log.Error("Failed to re-register node after decode error: ", regErr)
				return nil, err // Return original error
			}
			log.Info("Node re-registered successfully after decode error, retrying policy fetch...")
			
			// Retry the request with fresh registration
			return gw.LoadPoliciesFromDashboard(endpoint, secret, allowExplicit)
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

	return policies, err
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

func (gw *Gateway) LoadPoliciesFromRPC(store RPCDataLoader, orgId string, allowExplicit bool) (map[string]user.Policy, error) {
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

	policies, err := parsePoliciesFromRPC(rpcPolicies, allowExplicit)

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
