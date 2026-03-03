package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/rpc"
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

	JSONRPCMethods             []user.JSONRPCMethodLimit `json:"json_rpc_methods,omitempty"`
	JSONRPCMethodsAccessRights user.AccessControlRules   `json:"json_rpc_methods_access_rights,omitzero"`
	MCPPrimitives              []user.MCPPrimitiveLimit  `json:"mcp_primitives,omitempty"`
	MCPAccessRights            user.MCPAccessRights      `json:"mcp_access_rights,omitzero"`
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

	ad.JSONRPCMethods = d.JSONRPCMethods
	ad.JSONRPCMethodsAccessRights = d.JSONRPCMethodsAccessRights
	ad.MCPPrimitives = d.MCPPrimitives
	ad.MCPAccessRights = d.MCPAccessRights

	return ad
}

type DBPolicy struct {
	user.Policy
	AccessRights map[string]DBAccessDefinition `bson:"access_rights" json:"access_rights"`
}

// hasMCPFields returns true if the access definition contains any MCP-specific fields.
func hasMCPFields(ar user.AccessDefinition) bool {
	return len(ar.JSONRPCMethods) > 0 ||
		!ar.JSONRPCMethodsAccessRights.IsEmpty() ||
		len(ar.MCPPrimitives) > 0 ||
		!ar.MCPAccessRights.IsEmpty()
}

// validateMCPFieldsInAccessRights returns an error if any MCP-specific fields are set
// on an access right whose API is loaded and is not an MCP Proxy.
// Unknown APIs (not yet loaded) are skipped to avoid false negatives during bootstrap.
func (gw *Gateway) validateMCPFieldsInAccessRights(accessRights map[string]user.AccessDefinition) error {
	for apiID, ar := range accessRights {
		if !hasMCPFields(ar) {
			continue
		}
		spec := gw.getApiSpec(apiID)
		if spec == nil {
			continue
		}
		if !spec.IsMCP() {
			return fmt.Errorf("MCP fields can only be configured on MCP Proxies, API %q is not an MCP Proxy", apiID)
		}
		for _, p := range ar.MCPPrimitives {
			if err := p.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

// hasNonMCPFields returns true if the access definition contains any HTTP/REST or
// GraphQL fields that have no meaning in the MCP (JSON-RPC) protocol.
func hasNonMCPFields(ar user.AccessDefinition) bool {
	return len(ar.AllowedURLs) > 0 ||
		len(ar.Endpoints) > 0 ||
		len(ar.RestrictedTypes) > 0 ||
		len(ar.AllowedTypes) > 0 ||
		ar.DisableIntrospection ||
		len(ar.FieldAccessRights) > 0
}

// validateNonMCPFieldsOnMCPProxy returns an error if HTTP/REST or GraphQL access-right
// fields are set on a known MCP Proxy. Unknown APIs are skipped (fail-open).
func (gw *Gateway) validateNonMCPFieldsOnMCPProxy(accessRights map[string]user.AccessDefinition) error {
	for apiID, ar := range accessRights {
		if !hasNonMCPFields(ar) {
			continue
		}
		spec := gw.getApiSpec(apiID)
		if spec == nil {
			continue
		}
		if spec.IsMCP() {
			return fmt.Errorf("HTTP/REST and GraphQL fields cannot be configured on MCP Proxies, API %q is an MCP Proxy", apiID)
		}
	}
	return nil
}

func (d *DBPolicy) ToRegularPolicy() user.Policy {
	policy := d.Policy
	policy.AccessRights = make(map[string]user.AccessDefinition)

	for k, v := range d.AccessRights {
		policy.AccessRights[k] = v.ToRegularAD()
	}
	return policy
}

func LoadPoliciesFromFile(filePath string) ([]user.Policy, error) {
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

	var res = make([]user.Policy, 0, len(policies))
	for id, pol := range policies {
		pol.ID = lo.CoalesceOrEmpty(id, pol.ID) // prioritize id over ID in field or not?
		res = append(res, pol)
	}

	return res, nil
}

func LoadPoliciesFromDir(dir string) ([]user.Policy, error) {
	policies := make([]user.Policy, 0)
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
		policies = append(policies, *pol)
	}

	return policies, nil
}

// LoadPoliciesFromDashboard will connect and download Policies from a Tyk Dashboard instance.
func (gw *Gateway) LoadPoliciesFromDashboard(endpoint, secret string) ([]user.Policy, error) {
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

	return lo.Map(list.Message, func(item DBPolicy, _ int) user.Policy { return item.ToRegularPolicy() }), nil
}

func parsePoliciesFromRPC(list string) ([]user.Policy, error) {
	var policies []user.Policy

	if err := json.Unmarshal([]byte(list), &policies); err != nil {
		return nil, err
	}

	return policies, nil
}

func (gw *Gateway) LoadPoliciesFromRPC(store RPCDataLoader, orgId string) ([]user.Policy, error) {
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
