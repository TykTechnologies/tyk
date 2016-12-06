package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/TykTechnologies/logrus"
	"github.com/gorilla/mux"
	"github.com/rcrowley/goagain"
	"io"
	"net/http"
	"strings"
)

const RPCKeyPrefix string = "rpc:"
const BackupKeyBase string = "node-definition-backup:"

func getTagListAsString() string {
	tagList := ""
	if len(config.DBAppConfOptions.Tags) > 0 {
		tagList = strings.Join(config.DBAppConfOptions.Tags, "-")
	}

	return tagList
}

func SaveRPCDefinitionsBackup(thisList string) {
	log.Info("Storing RPC backup")
	tagList := getTagListAsString()

	log.Info("--> Connecting to DB")

	thisStore := &RedisClusterStorageManager{KeyPrefix: RPCKeyPrefix, HashKeys: false}
	connected := thisStore.Connect()

	log.Info("--> Connected to DB")

	if !connected {
		log.Error("--> RPC Backup save failed: redis connection failed")
		return
	}

	secret := rightPad2Len(config.Secret, "=", 32)
	cryptoText := encrypt([]byte(secret), thisList)
	rErr := thisStore.SetKey(BackupKeyBase+tagList, cryptoText, -1)
	if rErr != nil {
		log.Error("Failed to store node backup: ", rErr)
	}
}

func LoadDefinitionsFromRPCBackup() *[]*APISpec {
	tagList := getTagListAsString()
	checkKey := BackupKeyBase + tagList

	thisStore := &RedisClusterStorageManager{KeyPrefix: RPCKeyPrefix, HashKeys: false}

	connected := thisStore.Connect()
	log.Info("[RPC] --> Connected to DB")

	if !connected {
		log.Error("[RPC] --> RPC Backup recovery failed: redis connection failed")
		return nil
	}

	secret := rightPad2Len(config.Secret, "=", 32)
	cryptoText, rErr := thisStore.GetKey(checkKey)
	apiListAsString := decrypt([]byte(secret), cryptoText)

	if rErr != nil {
		log.Error("[RPC] --> Failed to get node backup (", checkKey, "): ", rErr)
		return nil
	}

	a := APIDefinitionLoader{}
	return a.processRPCDefinitions(apiListAsString)
}

func doLoadWithBackup(specs *[]*APISpec) {

	log.Warning("[RPC Backup] --> Load Policies too!")

	if len(*specs) == 0 {
		log.WithFields(logrus.Fields{
			"prefix": "main",
		}).Warning("No API Definitions found, not loading backup")
		return
	}

	// Reset the JSVM
	GlobalEventsJSVM.Init(config.TykJSPath)
	log.Warning("[RPC Backup] --> Initialised JSVM")

	newRouter := mux.NewRouter()
	mainRouter = newRouter

	var newMuxes *mux.Router
	if getHostName() != "" {
		newMuxes = newRouter.Host(getHostName()).Subrouter()
	} else {
		newMuxes = newRouter
	}

	log.Warning("[RPC Backup] --> Set up routers")
	log.Warning("[RPC Backup] --> Loading endpoints")

	loadAPIEndpoints(newMuxes)

	log.Warning("[RPC Backup] --> Loading APIs")
	loadApps(specs, newMuxes)
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

	l, goAgainErr := goagain.Listener()
	var listenerErr error
	
	l, listenerErr = generateListener(l) 
	if listenerErr != nil {
		log.Info("Failed to generate listener!")
	}

	listen(l, goAgainErr)
}

// encrypt string to base64 crypto using AES
func encrypt(key []byte, text string) string {
	// key := []byte(keyText)
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

	return fmt.Sprintf("%s", ciphertext)
}

func rightPad2Len(s string, padStr string, overallLen int) string {
	var padCountInt int
	padCountInt = 1 + ((overallLen - len(padStr)) / len(padStr))
	var retStr = s + strings.Repeat(padStr, padCountInt)
	return retStr[:overallLen]
}
