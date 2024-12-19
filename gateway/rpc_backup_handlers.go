package gateway

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/TykTechnologies/tyk/internal/crypto"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

const RPCKeyPrefix = "rpc:"
const BackupApiKeyBase = "node-definition-backup:"
const BackupPolicyKeyBase = "node-policy-backup:"

func getTagListAsString(tags []string) string {
	tagList := ""
	if len(tags) > 0 {
		tagList = strings.Join(tags, "-")
	}

	return tagList
}

func (gw *Gateway) LoadDefinitionsFromRPCBackup() ([]*APISpec, error) {
	tagList := getTagListAsString(gw.GetConfig().DBAppConfOptions.Tags)
	checkKey := BackupApiKeyBase + tagList

	store := storage.RedisCluster{KeyPrefix: RPCKeyPrefix, ConnectionHandler: gw.StorageConnectionHandler}
	connected := store.Connect()
	log.Info("[RPC] --> Loading API definitions from backup")

	if !connected {
		return nil, errors.New("[RPC] --> RPC Backup recovery failed: redis connection failed")
	}

	secret := crypto.GetPaddedString(gw.GetConfig().Secret)
	cryptoText, err := store.GetKey(checkKey)
	if err != nil {
		return nil, errors.New("[RPC] --> Failed to get node backup (" + checkKey + "): " + err.Error())
	}

	apiListAsString := crypto.Decrypt([]byte(secret), cryptoText)

	a := APIDefinitionLoader{Gw: gw}
	return a.processRPCDefinitions(apiListAsString, gw)
}

func (gw *Gateway) saveRPCDefinitionsBackup(list string) error {
	if !json.Valid([]byte(list)) {
		return errors.New("--> RPC Backup save failure: wrong format, skipping.")
	}

	log.Info("Storing RPC Definitions backup")
	tagList := getTagListAsString(gw.GetConfig().DBAppConfOptions.Tags)

	log.Info("--> Connecting to DB")

	store := storage.RedisCluster{KeyPrefix: RPCKeyPrefix, ConnectionHandler: gw.StorageConnectionHandler}
	connected := store.Connect()

	log.Info("--> Connected to DB")

	if !connected {
		return errors.New("--> RPC Backup save failed: redis connection failed")
	}

	secret := crypto.GetPaddedString(gw.GetConfig().Secret)
	cryptoText := crypto.Encrypt([]byte(secret), list)
	err := store.SetKey(BackupApiKeyBase+tagList, cryptoText, -1)
	if err != nil {
		return errors.New("Failed to store node backup: " + err.Error())
	}

	return nil
}

func (gw *Gateway) LoadPoliciesFromRPCBackup() (map[string]user.Policy, error) {
	tagList := getTagListAsString(gw.GetConfig().DBAppConfOptions.Tags)
	checkKey := BackupPolicyKeyBase + tagList

	store := storage.RedisCluster{KeyPrefix: RPCKeyPrefix, ConnectionHandler: gw.StorageConnectionHandler}

	connected := store.Connect()
	log.Info("[RPC] Loading Policies from backup")

	if !connected {
		return nil, errors.New("[RPC] --> RPC Policy Backup recovery failed: redis connection failed")
	}

	secret := crypto.GetPaddedString(gw.GetConfig().Secret)
	cryptoText, err := store.GetKey(checkKey)
	listAsString := crypto.Decrypt([]byte(secret), cryptoText)

	if err != nil {
		return nil, errors.New("[RPC] --> Failed to get node policy backup (" + checkKey + "): " + err.Error())
	}

	if policies, err := parsePoliciesFromRPC(listAsString, gw.GetConfig().Policies.AllowExplicitPolicyID); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "policy",
		}).Error("Failed decode: ", err)
		return nil, err
	} else {
		return policies, nil
	}
}

func (gw *Gateway) saveRPCPoliciesBackup(list string) error {
	if !json.Valid([]byte(list)) {
		return errors.New("--> RPC Backup save failure: wrong format, skipping.")
	}

	log.Info("Storing RPC policies backup")
	tagList := getTagListAsString(gw.GetConfig().DBAppConfOptions.Tags)

	log.Info("--> Connecting to DB")

	store := storage.RedisCluster{KeyPrefix: RPCKeyPrefix, ConnectionHandler: gw.StorageConnectionHandler}
	connected := store.Connect()

	log.Info("--> Connected to DB")

	if !connected {
		return errors.New("--> RPC Backup save failed: redis connection failed")
	}

	cryptoText := crypto.Encrypt(crypto.GetPaddedString(gw.GetConfig().Secret), list)
	err := store.SetKey(BackupPolicyKeyBase+tagList, cryptoText, -1)
	if err != nil {
		return errors.New("Failed to store node backup: " + err.Error())
	}

	return nil
}
