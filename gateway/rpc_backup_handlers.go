package gateway

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/internal/compression"
	"github.com/TykTechnologies/tyk/internal/crypto"
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

	store := &storage.RedisCluster{KeyPrefix: RPCKeyPrefix, ConnectionHandler: gw.StorageConnectionHandler}
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

	decrypted := crypto.Decrypt([]byte(secret), cryptoText)

	apiList, err := gw.decodeAPIBackup(decrypted)
	if err != nil {
		return nil, err
	}

	a := APIDefinitionLoader{Gw: gw}
	return a.processRPCDefinitions(apiList, gw)
}

func (gw *Gateway) saveRPCDefinitionsBackup(list string) error {
	if !json.Valid([]byte(list)) {
		return errors.New("--> RPC Backup save failure: wrong format, skipping.")
	}

	log.Info("Storing RPC Definitions backup")
	tagList := getTagListAsString(gw.GetConfig().DBAppConfOptions.Tags)

	log.Info("--> Connecting to DB")

	store := &storage.RedisCluster{KeyPrefix: RPCKeyPrefix, ConnectionHandler: gw.StorageConnectionHandler}
	connected := store.Connect()

	log.Info("--> Connected to DB")

	if !connected {
		return errors.New("--> RPC Backup save failed: redis connection failed")
	}

	secret := crypto.GetPaddedString(gw.GetConfig().Secret)
	dataToEncrypt := gw.encodeAPIBackup(list)

	cryptoText := crypto.Encrypt([]byte(secret), dataToEncrypt)
	if err := store.SetKey(BackupApiKeyBase+tagList, cryptoText, -1); err != nil {
		return errors.New("Failed to store node backup: " + err.Error())
	}

	return nil
}

// encodeAPIBackup compresses and encodes API backup data if compression is enabled
func (gw *Gateway) encodeAPIBackup(list string) string {
	if !gw.GetConfig().Storage.CompressAPIDefinitions {
		log.Debug("[RPC] --> API definition compression disabled")
		return list
	}

	compressed, err := compression.CompressZstd([]byte(list))
	if err != nil {
		log.WithError(err).Warning("[RPC] --> Failed to compress API definitions, falling back to uncompressed")
		return list
	}

	encoded := base64.StdEncoding.EncodeToString(compressed)
	log.Debug("[RPC] --> API definitions compressed and base64-encoded")
	return "zstd::" + encoded
}

// decodeAPIBackup decodes and decompresses API backup data
func (gw *Gateway) decodeAPIBackup(decrypted string) (string, error) {
	// Check for new format with prefix
	if strings.HasPrefix(decrypted, "zstd::") {
		encoded := strings.TrimPrefix(decrypted, "zstd::")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", errors.New("[RPC] --> Failed to decode compressed backup: " + err.Error())
		}

		decompressed, err := compression.DecompressZstd(decoded)
		if err != nil {
			return "", errors.New("[RPC] --> Failed to decompress backup: " + err.Error())
		}

		log.Debug("[RPC] --> Loaded compressed API definitions from backup")

		return string(decompressed), nil
	}

	// Uncompressed
	log.Debug("[RPC] --> Loaded uncompressed API definitions from backup")
	return decrypted, nil
}

func (gw *Gateway) LoadPoliciesFromRPCBackup() (map[string]user.Policy, error) {
	tagList := getTagListAsString(gw.GetConfig().DBAppConfOptions.Tags)
	checkKey := BackupPolicyKeyBase + tagList

	store := &storage.RedisCluster{KeyPrefix: RPCKeyPrefix, ConnectionHandler: gw.StorageConnectionHandler}
	connected := store.Connect()

	log.Info("[RPC] Loading Policies from backup")

	if !connected {
		return nil, errors.New("[RPC] --> RPC Policy Backup recovery failed: redis connection failed")
	}

	secret := crypto.GetPaddedString(gw.GetConfig().Secret)
	cryptoText, err := store.GetKey(checkKey)
	if err != nil {
		return nil, errors.New("[RPC] --> Failed to get node policy backup (" + checkKey + "): " + err.Error())
	}

	listAsString := crypto.Decrypt([]byte(secret), cryptoText)

	if policies, err := parsePoliciesFromRPC(listAsString); err != nil {
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

	secret := crypto.GetPaddedString(gw.GetConfig().Secret)
	cryptoText := crypto.Encrypt([]byte(secret), list)
	err := store.SetKey(BackupPolicyKeyBase+tagList, cryptoText, -1)
	if err != nil {
		return errors.New("Failed to store node backup: " + err.Error())
	}

	return nil
}
