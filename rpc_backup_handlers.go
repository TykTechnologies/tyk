package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/Sirupsen/logrus"
)

const RPCKeyPrefix = "rpc:"
const BackupKeyBase = "node-definition-backup:"

func getTagListAsString() string {
	tagList := ""
	if len(config.DBAppConfOptions.Tags) > 0 {
		tagList = strings.Join(config.DBAppConfOptions.Tags, "-")
	}

	return tagList
}

func saveRPCDefinitionsBackup(list string) {
	log.Info("Storing RPC backup")
	tagList := getTagListAsString()

	log.Info("--> Connecting to DB")

	store := &RedisClusterStorageManager{KeyPrefix: RPCKeyPrefix, HashKeys: false}
	connected := store.Connect()

	log.Info("--> Connected to DB")

	if !connected {
		log.Error("--> RPC Backup save failed: redis connection failed")
		return
	}

	secret := rightPad2Len(config.Secret, "=", 32)
	cryptoText := encrypt([]byte(secret), list)
	err := store.SetKey(BackupKeyBase+tagList, cryptoText, -1)
	if err != nil {
		log.Error("Failed to store node backup: ", err)
	}
}

func LoadDefinitionsFromRPCBackup() []*APISpec {
	tagList := getTagListAsString()
	checkKey := BackupKeyBase + tagList

	store := &RedisClusterStorageManager{KeyPrefix: RPCKeyPrefix, HashKeys: false}

	connected := store.Connect()
	log.Info("[RPC] --> Connected to DB")

	if !connected {
		log.Error("[RPC] --> RPC Backup recovery failed: redis connection failed")
		return nil
	}

	secret := rightPad2Len(config.Secret, "=", 32)
	cryptoText, err := store.GetKey(checkKey)
	apiListAsString := decrypt([]byte(secret), cryptoText)

	if err != nil {
		log.Error("[RPC] --> Failed to get node backup (", checkKey, "): ", err)
		return nil
	}

	a := APIDefinitionLoader{}
	return a.processRPCDefinitions(apiListAsString)
}

func doLoadWithBackup(specs []*APISpec) {

	log.Warning("[RPC Backup] --> Load Policies too!")

	if len(specs) == 0 {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Warning("No API Definitions found, not loading backup")
		return
	}

	// Reset the JSVM
	GlobalEventsJSVM.Init()
	log.Warning("[RPC Backup] --> Initialised JSVM")

	newRouter := mux.NewRouter()
	mainRouter = newRouter

	log.Warning("[RPC Backup] --> Set up routers")
	log.Warning("[RPC Backup] --> Loading endpoints")

	loadAPIEndpoints(newRouter)

	log.Warning("[RPC Backup] --> Loading APIs")
	loadApps(specs, newRouter)
	log.Warning("[RPC Backup] --> API Load Done")

	newServeMux := http.NewServeMux()
	newServeMux.Handle("/", mainRouter)

	http.DefaultServeMux = newServeMux
	log.Warning("[RPC Backup] --> Replaced muxer")

	log.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("API backup load complete")

	log.Warning("[RPC Backup] --> Ready to listen")
	RPC_EmergencyModeLoaded = true

	l, err := generateListener(0)
	if err != nil {
		log.Error("Failed to generate listener:", err)
	}
	listen(l, nil, nil)
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
