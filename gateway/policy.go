package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/buger/jsonparser"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/rpc"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/user"
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
	*user.Policy
	AccessRights  map[string]DBAccessDefinition `bson:"access_rights" json:"access_rights"`
	checksumMatch bool
	checksum      string
}

func (d *DBPolicy) ToRegularPolicy() *user.Policy {
	policy := d.Policy
	policy.AccessRights = make(map[string]user.AccessDefinition)

	for k, v := range d.AccessRights {
		policy.AccessRights[k] = v.ToRegularAD()
	}
	return policy
}

func LoadPoliciesFromFile(filePath string) map[string]*user.Policy {
	f, err := os.Open(filePath)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "policy",
		}).Error("Couldn't open policy file: ", err)
		return nil
	}
	defer f.Close()

	var policies map[string]*user.Policy
	if err := json.NewDecoder(f).Decode(&policies); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "policy",
		}).Error("Couldn't unmarshal policies: ", err)
	}
	return policies
}

func LoadPoliciesFromDir(dir string) map[string]*user.Policy {
	policies := make(map[string]*user.Policy)
	// Grab json files from directory
	paths, _ := filepath.Glob(filepath.Join(dir, "*.json"))
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
		policies[pol.ID] = pol
	}
	return policies
}

// LoadPoliciesFromDashboard will connect and download Policies from a Tyk Dashboard instance.
func (gw *Gateway) LoadPoliciesFromDashboard(endpoint, secret string, allowExplicit bool) map[string]*user.Policy {

	// Get the definitions
	newRequest, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Error("Failed to create request: ", err)
	}

	newRequest.Header.Set("authorization", secret)
	newRequest.Header.Set("x-tyk-nodeid", gw.GetNodeID())

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
		return nil
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		log.Error("Policy request login failure, Response was: ", string(body))
		gw.reLogin()
		return nil
	}

	// Extract Policies
	var list struct {
		Message []DBPolicy
		Nonce   string
	}

	nonce, err := jsonparser.GetString(body, "Nonce")
	if err != nil {
		log.Error("Failed to decode Nonce: ", err)
		return nil
	}
	list.Nonce = nonce

	policiesJSON, _, _, err := jsonparser.Get(body, "Message")
	if err != nil {
		log.Error("Failed to decode Message: ", err)
		return nil
	}

	jsonparser.ArrayEach(policiesJSON, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		hash := sha256.Sum256(value)
		checksum := hex.EncodeToString(hash[:])

		dbPolicy := DBPolicy{}
		if policy, found := gw.polsChecksums[checksum]; !found {
			json.Unmarshal(value, &dbPolicy)
		} else {
			dbPolicy.Policy = policy
			dbPolicy.checksumMatch = true
		}
		dbPolicy.checksum = checksum

		list.Message = append(list.Message, dbPolicy)
	})

	gw.ServiceNonceMutex.Lock()
	gw.ServiceNonce = list.Nonce
	gw.ServiceNonceMutex.Unlock()
	log.Debug("Loading Policies Finished: Nonce Set: ", list.Nonce)

	policies := make(map[string]*user.Policy, len(list.Message))
	gw.polsChecksums = make(map[string]*user.Policy, len(list.Message))

	log.WithFields(logrus.Fields{
		"prefix": "policy",
	}).Info("Processing policy list")
	for _, p := range list.Message {
		if p.checksumMatch {
			gw.polsChecksums[p.checksum] = p.Policy
			policies[p.ID] = p.Policy
			continue
		}

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
		gw.polsChecksums[p.checksum] = policies[id]
	}

	return policies
}

func parsePoliciesFromRPC(gw *Gateway, list string, allowExplicit bool) (map[string]*user.Policy, error) {
	var dbPolicyList []DBPolicy

	jsonparser.ArrayEach([]byte(list), func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		hash := sha256.Sum256(value)
		checksum := hex.EncodeToString(hash[:])

		dbPolicy := DBPolicy{}
		if policy, found := gw.polsChecksums[checksum]; !found {
			json.Unmarshal(value, &dbPolicy)
		} else {
			dbPolicy.Policy = policy
			dbPolicy.checksumMatch = true
		}
		dbPolicy.checksum = checksum

		dbPolicyList = append(dbPolicyList, dbPolicy)
	})

	policies := make(map[string]*user.Policy, len(dbPolicyList))
	gw.polsChecksums = make(map[string]*user.Policy, len(dbPolicyList))

	for _, p := range dbPolicyList {
		pol := p.Policy
		gw.polsChecksums[p.checksum] = pol

		if p.checksumMatch {
			policies[p.ID] = pol
			continue
		}

		id := pol.MID.Hex()
		if allowExplicit && pol.ID != "" {
			id = pol.ID
		}
		pol.ID = id
		policies[id] = pol

	}

	return policies, nil
}

func (gw *Gateway) LoadPoliciesFromRPC(store RPCDataLoader, orgId string, allowExplicit bool) (map[string]*user.Policy, error) {
	if rpc.IsEmergencyMode() {
		return gw.LoadPoliciesFromRPCBackup()
	}

	if !store.Connect() {
		return nil, errors.New("Policies backup: Failed connecting to database")
	}

	rpcPolicies := store.GetPolicies(orgId)

	policies, err := parsePoliciesFromRPC(gw, rpcPolicies, allowExplicit)

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
