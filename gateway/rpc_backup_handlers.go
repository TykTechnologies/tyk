package gateway

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/sirupsen/logrus"

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

	// Detect format using Zstd magic bytes
	var apiList string
	if isZstdCompressed([]byte(decrypted)) {
		// Compressed format, decompress it
		decompressed, err := decompressData([]byte(decrypted))
		if err != nil {
			return nil, errors.New("[RPC] --> Failed to decompress backup: " + err.Error())
		}
		apiList = string(decompressed)
		log.Debug("[RPC] --> Loaded compressed API definitions from backup")
	} else {
		// Uncompressed format, use as is
		apiList = decrypted
		log.Debug("[RPC] --> Loaded uncompressed API definitions from backup")
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

	// Check API definition compression is enabled
	var dataToEncrypt string
	if gw.GetConfig().Storage.CompressAPIDefinitions {
		compressed, err := compressData([]byte(list))
		if err != nil {
			log.WithError(err).Warning("[RPC] --> Failed to compress API definitions, falling back to uncompressed")
			dataToEncrypt = list
		} else {
			dataToEncrypt = string(compressed)
		}
	} else {
		// No compression
		dataToEncrypt = list
		log.Debug("[RPC] --> API definition compression disabled")
	}

	cryptoText := crypto.Encrypt(secret, dataToEncrypt)
	if err := store.SetKey(BackupApiKeyBase+tagList, cryptoText, -1); err != nil {
		return errors.New("Failed to store node backup: " + err.Error())
	}

	return nil
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
	listAsString := crypto.Decrypt([]byte(secret), cryptoText)

	if err != nil {
		return nil, errors.New("[RPC] --> Failed to get node policy backup (" + checkKey + "): " + err.Error())
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

	cryptoText := crypto.Encrypt(crypto.GetPaddedString(gw.GetConfig().Secret), list)
	err := store.SetKey(BackupPolicyKeyBase+tagList, cryptoText, -1)
	if err != nil {
		return errors.New("Failed to store node backup: " + err.Error())
	}

	return nil
}

// compressData compresses data using Zstd compression
// Returns the compressed data and logs compression statistics
func compressData(data []byte) ([]byte, error) {
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}
	defer encoder.Close()

	compressed := encoder.EncodeAll(data, make([]byte, 0, len(data)))

	compressionRatio := float64(len(data)-len(compressed)) / float64(len(data)) * 100
	log.WithFields(logrus.Fields{
		"original_size":     len(data),
		"compressed_size":   len(compressed),
		"compression_ratio": compressionRatio,
	}).Debug("Data compressed with Zstd")

	return compressed, nil
}

// decompressData decompresses Zstd-compressed data
func decompressData(data []byte) ([]byte, error) {
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer decoder.Close()

	decompressed, err := decoder.DecodeAll(data, nil)
	if err != nil {
		return nil, err
	}

	log.WithField("decompressed_size", len(decompressed)).Debug("Data decompressed with Zstd")
	return decompressed, nil
}

// isZstdCompressed checks if data is Zstd-compressed by examining the magic bytes.
// Zstd frames start with a 4-byte magic number: 0x28, 0xB5, 0x2F, 0xFD
// This is more reliable than JSON validation as it explicitly identifies the compression format.
func isZstdCompressed(data []byte) bool {
	// Zstd magic number (little-endian): 0xFD2FB528
	// As bytes: 0x28, 0xB5, 0x2F, 0xFD
	if len(data) < 4 {
		return false
	}
	return data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD
}
