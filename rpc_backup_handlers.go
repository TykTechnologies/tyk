package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

const RPCKeyPrefix = "rpc:"
const BackupApiKeyBase = "node-definition-backup:"
const BackupPolicyKeyBase = "node-policy-backup:"

func getTagListAsString() string {
	tagList := ""
	if len(config.Global.DBAppConfOptions.Tags) > 0 {
		tagList = strings.Join(config.Global.DBAppConfOptions.Tags, "-")
	}

	return tagList
}

func LoadDefinitionsFromRPCBackup() []*APISpec {
	tagList := getTagListAsString()
	checkKey := BackupApiKeyBase + tagList

	store := storage.RedisCluster{KeyPrefix: RPCKeyPrefix}
	connected := store.Connect()
	log.Info("[RPC] --> Loading API definitions from backup")

	if !connected {
		log.Error("[RPC] --> RPC Backup recovery failed: redis connection failed")
		return nil
	}

	secret := rightPad2Len(config.Global.Secret, "=", 32)
	cryptoText, err := store.GetKey(checkKey)
	apiListAsString := decrypt([]byte(secret), cryptoText)

	if err != nil {
		log.Error("[RPC] --> Failed to get node backup (", checkKey, "): ", err)
		return nil
	}

	a := APIDefinitionLoader{}
	return a.processRPCDefinitions(apiListAsString)
}

func saveRPCDefinitionsBackup(list string) {
	log.Info("Storing RPC Definitions backup")
	tagList := getTagListAsString()

	log.Info("--> Connecting to DB")

	store := storage.RedisCluster{KeyPrefix: RPCKeyPrefix}
	connected := store.Connect()

	log.Info("--> Connected to DB")

	if !connected {
		log.Error("--> RPC Backup save failed: redis connection failed")
		return
	}

	secret := rightPad2Len(config.Global.Secret, "=", 32)
	cryptoText := encrypt([]byte(secret), list)
	err := store.SetKey(BackupApiKeyBase+tagList, cryptoText, -1)
	if err != nil {
		log.Error("Failed to store node backup: ", err)
	}
}

func LoadPoliciesFromRPCBackup() map[string]user.Policy {
	tagList := getTagListAsString()
	checkKey := BackupPolicyKeyBase + tagList

	store := storage.RedisCluster{KeyPrefix: RPCKeyPrefix}

	connected := store.Connect()
	log.Info("[RPC] Loading Policies from backup")

	if !connected {
		log.Error("[RPC] --> RPC Policy Backup recovery failed: redis connection failed")
		return nil
	}

	secret := rightPad2Len(config.Global.Secret, "=", 32)
	cryptoText, err := store.GetKey(checkKey)
	listAsString := decrypt([]byte(secret), cryptoText)

	if err != nil {
		log.Error("[RPC] --> Failed to get node policy backup (", checkKey, "): ", err)
		return nil
	}

	if policies, err := parsePoliciesFromRPC(listAsString); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "policy",
		}).Error("Failed decode: ", err)
		return nil
	} else {
		return policies
	}
}

func saveRPCPoliciesBackup(list string) {
	log.Info("Storing RPC policies backup")
	tagList := getTagListAsString()

	log.Info("--> Connecting to DB")

	store := storage.RedisCluster{KeyPrefix: RPCKeyPrefix}
	connected := store.Connect()

	log.Info("--> Connected to DB")

	if !connected {
		log.Error("--> RPC Backup save failed: redis connection failed")
		return
	}

	secret := rightPad2Len(config.Global.Secret, "=", 32)
	cryptoText := encrypt([]byte(secret), list)
	err := store.SetKey(BackupPolicyKeyBase+tagList, cryptoText, -1)
	if err != nil {
		log.Error("Failed to store node backup: ", err)
	}
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
