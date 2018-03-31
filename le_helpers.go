package main

import (
	"encoding/json"

	"github.com/Sirupsen/logrus"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"golang.org/x/crypto/acme/autocert"
	"time"
	"net/http"
	"net"
	"context"
	"errors"
)

// Errors
var ErrRedisConnection = errors.New("--> acme/autocert: could not connect to the redis instance")

// Constants
const LEKeyPrefix = "le_ssl:"

// Saves the domains to redis
type RedisCache struct {
	domains map[string][]byte
}

func NewRedisCache() *RedisCache {
	return &RedisCache{
		domains: make(map[string][]byte),
	}
}

func ConnectToRedisStore() (*storage.RedisCluster, error){
	store := storage.RedisCluster{KeyPrefix: LEKeyPrefix}

	connected := store.Connect()
	log.Debug("[SSL] --> Connected to DB")

	if !connected {
		log.Error("[SSL] --> SSL Backup recovery failed: redis connection failed")
		return nil, ErrRedisConnection
	}

	return &store, nil
}

func (m RedisCache) Get(ctx context.Context, name string) ([]byte, error) {
	// If we already have a in-memory save
	if m.domains[name] != nil {
		return m.domains[name], nil
	}

	checkKey := "cache-" + name

	store, err := ConnectToRedisStore()
	if err != nil {
		return nil, err
	}

	cryptoText, err := store.GetKey(checkKey)
	if err != nil {
		log.Warning("[SSL] --> No SSL backup: ", err)
		return nil, autocert.ErrCacheMiss
	}

	secret := rightPad2Len(config.Global.Secret, "=", 32)
	sslState := decrypt([]byte(secret), cryptoText)

	return []byte(sslState), nil
}

// Stores the ssl certificates to the redis and local storage
func (m RedisCache) Put(ctx context.Context, name string, data []byte) error {
	m.domains[name] = data

	log.Debug("Storing SSL backup")

	store, err := ConnectToRedisStore()
	if err != nil {
		return err
	}

	secret := rightPad2Len(config.Global.Secret, "=", 32)
	cryptoText := encrypt([]byte(secret), string(data))

	if err := store.SetKey("cache-" + name, cryptoText, -1); err != nil {
		log.Error("[SSL] --> Failed to store SSL backup: ", err)
		return ErrRedisConnection
	}

	return nil
}

// Deletes the ssl certificates from the redis and local storage
func (m RedisCache) Delete(ctx context.Context, name string) error {
	delete(m.domains, name)

	log.Debug("Deleting SSL backup")

	store, err := ConnectToRedisStore()
	if err != nil {
		return err
	}

	store.DeleteKey(name)

	return nil
}

type LE_ServerInfo struct {
	HostName string
	ID       string
}

func onLESSLStatusReceivedHandler(payload string) {
	serverData := LE_ServerInfo{}
	if err := json.Unmarshal([]byte(payload), &serverData); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed unmarshal server data: ", err)
		return
	}

	log.Debug("Received LE data: ", serverData)

	// not great
	if serverData.ID != NodeID {
		log.Info("Received Redis LE change notification!")

	}

	log.Info("Received Redis LE change notification from myself, ignoring")

}

func AcceptLetsEncryptTOS(tosURL string) bool {
	return config.Global.HttpServerOptions.AcceptLetsEncryptTOS
}

func MakeLEValidationHttpServer() *http.Server {
	// Redirects to the ssl endpoint
	handleRedirect := func(w http.ResponseWriter, r *http.Request) {
		newURI := "https://" + r.Host + r.URL.String()
		http.Redirect(w, r, newURI, http.StatusFound)
	}
	mux := &http.ServeMux{}
	mux.HandleFunc("/", handleRedirect)

	validationServer := &http.Server{
		Addr: ":80",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      mux,
	}

	return validationServer
}

func CreateLEValidationServerListener(srv *http.Server) (net.Listener, error) {
	addr := srv.Addr
	if addr == "" {
		addr = ":http"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	return ln, nil
}