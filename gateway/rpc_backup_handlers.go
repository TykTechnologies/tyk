package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
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

// backupKind identifies the type of data being compressed or decompressed,
// used for log and error messages. Defining it as a named type lets the
// compiler catch mismatched or missing kind arguments at the call sites.
type backupKind string

const (
	backupKindAPIDefinitions backupKind = "API Definitions"
	backupKindPolicies       backupKind = "Policies"
)

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

	decrypted := crypto.Decrypt(secret, cryptoText)

	apiList, err := gw.decompressAPIBackup(decrypted)
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
	dataToEncrypt := gw.compressAPIBackup(list)

	cryptoText := crypto.Encrypt(secret, dataToEncrypt)
	if err := store.SetKey(BackupApiKeyBase+tagList, cryptoText, -1); err != nil {
		return errors.New("Failed to store node backup: " + err.Error())
	}

	return nil
}

// compressBackup compresses backup data using Zstd if enabled, logging with the
// provided kind label. Returns the original data unchanged if compression is
// disabled or fails.
func (gw *Gateway) compressBackup(list string, enabled bool, kind backupKind) string {
	if !enabled {
		log.Debugf("[RPC] --> %s compression disabled", kind)
		return list
	}

	compressed, err := compression.CompressZstd([]byte(list))
	if err != nil {
		log.WithError(err).Errorf("[RPC] --> Failed to compress %s, storing uncompressed", kind)
		return list
	}
	log.Debugf("[RPC] --> %s compressed with Zstd", kind)
	return string(compressed)
}

// decompressBackup decompresses Zstd-compressed backup data if the magic bytes
// are present, logging with the provided kind label. The max decompressed size
// is enforced by DecompressZstd via the decoder pool. Uncompressed data is
// returned as-is; the size limit does not apply because there is no expansion.
func (gw *Gateway) decompressBackup(decrypted string, kind backupKind) (string, error) {
	data := []byte(decrypted)

	if compression.IsZstdCompressed(data) {
		decompressed, err := compression.DecompressZstd(data)
		if err != nil {
			return "", fmt.Errorf("[RPC] --> Failed to decompress %s backup: %w", kind, err)
		}

		log.Debugf("[RPC] --> Loaded compressed %s from backup", kind)
		return string(decompressed), nil
	}

	log.Debugf("[RPC] --> Loaded uncompressed %s from backup", kind)
	return decrypted, nil
}

func (gw *Gateway) compressAPIBackup(list string) string {
	return gw.compressBackup(list, gw.GetConfig().Storage.CompressAPIDefinitions, backupKindAPIDefinitions)
}

func (gw *Gateway) decompressAPIBackup(decrypted string) (string, error) {
	return gw.decompressBackup(decrypted, backupKindAPIDefinitions)
}

func (gw *Gateway) compressPolicyBackup(list string) string {
	return gw.compressBackup(list, gw.GetConfig().Storage.CompressPolicies, backupKindPolicies)
}

func (gw *Gateway) decompressPolicyBackup(decrypted string) (string, error) {
	return gw.decompressBackup(decrypted, backupKindPolicies)
}

func (gw *Gateway) LoadPoliciesFromRPCBackup() ([]user.Policy, error) {
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

	decrypted := crypto.Decrypt(secret, cryptoText)

	listAsString, err := gw.decompressPolicyBackup(decrypted)
	if err != nil {
		return nil, err
	}

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
	dataToEncrypt := gw.compressPolicyBackup(list)
	cryptoText := crypto.Encrypt(secret, dataToEncrypt)
	err := store.SetKey(BackupPolicyKeyBase+tagList, cryptoText, -1)
	if err != nil {
		return errors.New("Failed to store node backup: " + err.Error())
	}

	return nil
}
