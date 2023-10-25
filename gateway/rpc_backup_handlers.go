package gateway

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"

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

	store := storage.RedisCluster{KeyPrefix: RPCKeyPrefix, RedisController: gw.RedisController}
	connected := store.Connect()
	log.Info("[RPC] --> Loading API definitions from backup")

	if !connected {
		return nil, errors.New("[RPC] --> RPC Backup recovery failed: redis connection failed")
	}

	secret := rightPad2Len(gw.GetConfig().Secret, "=", 32)
	cryptoText, err := store.GetKey(checkKey)
	if err != nil {
		return nil, errors.New("[RPC] --> Failed to get node backup (" + checkKey + "): " + err.Error())
	}

	apiListAsString := decrypt([]byte(secret), cryptoText)

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

	store := storage.RedisCluster{KeyPrefix: RPCKeyPrefix, RedisController: gw.RedisController}
	connected := store.Connect()

	log.Info("--> Connected to DB")

	if !connected {
		return errors.New("--> RPC Backup save failed: redis connection failed")
	}

	secret := rightPad2Len(gw.GetConfig().Secret, "=", 32)
	cryptoText := encrypt([]byte(secret), list)
	err := store.SetKey(BackupApiKeyBase+tagList, cryptoText, -1)
	if err != nil {
		return errors.New("Failed to store node backup: " + err.Error())
	}

	return nil
}

func (gw *Gateway) LoadPoliciesFromRPCBackup() (map[string]user.Policy, error) {
	tagList := getTagListAsString(gw.GetConfig().DBAppConfOptions.Tags)
	checkKey := BackupPolicyKeyBase + tagList

	store := storage.RedisCluster{KeyPrefix: RPCKeyPrefix, RedisController: gw.RedisController}

	connected := store.Connect()
	log.Info("[RPC] Loading Policies from backup")

	if !connected {
		return nil, errors.New("[RPC] --> RPC Policy Backup recovery failed: redis connection failed")
	}

	secret := rightPad2Len(gw.GetConfig().Secret, "=", 32)
	cryptoText, err := store.GetKey(checkKey)
	listAsString := decrypt([]byte(secret), cryptoText)

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

	store := storage.RedisCluster{KeyPrefix: RPCKeyPrefix, RedisController: gw.RedisController}
	connected := store.Connect()

	log.Info("--> Connected to DB")

	if !connected {
		return errors.New("--> RPC Backup save failed: redis connection failed")
	}

	secret := rightPad2Len(gw.GetConfig().Secret, "=", 32)
	cryptoText := encrypt([]byte(secret), list)
	err := store.SetKey(BackupPolicyKeyBase+tagList, cryptoText, -1)
	if err != nil {
		return errors.New("Failed to store node backup: " + err.Error())
	}

	return nil
}

// encrypt string to base64 crypto using AES
func encrypt(key []byte, text string) string {
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Error(err)
		return ""
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Error(err)
		return ""
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}

// decrypt from base64 to decrypted string
func decrypt(key []byte, cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Error(err)
		return ""
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		log.Error("ciphertext too short")
		return ""
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext)
}

func rightPad2Len(s, padStr string, overallLen int) string {
	padCountInt := 1 + (overallLen-len(padStr))/len(padStr)
	retStr := s + strings.Repeat(padStr, padCountInt)
	return retStr[:overallLen]
}
