package gateway

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis"

	"github.com/TykTechnologies/goverify"
	"github.com/TykTechnologies/tyk/v3/config"
	"github.com/TykTechnologies/tyk/v3/storage"
)

type NotificationCommand string

const (
	RedisPubSubChannel = "tyk.cluster.notifications"

	NoticeApiUpdated             NotificationCommand = "ApiUpdated"
	NoticeApiRemoved             NotificationCommand = "ApiRemoved"
	NoticeApiAdded               NotificationCommand = "ApiAdded"
	NoticeGroupReload            NotificationCommand = "GroupReload"
	NoticePolicyChanged          NotificationCommand = "PolicyChanged"
	NoticeConfigUpdate           NotificationCommand = "NoticeConfigUpdated"
	NoticeDashboardZeroConf      NotificationCommand = "NoticeDashboardZeroConf"
	NoticeDashboardConfigRequest NotificationCommand = "NoticeDashboardConfigRequest"
	NoticeGatewayConfigResponse  NotificationCommand = "NoticeGatewayConfigResponse"
	NoticeGatewayDRLNotification NotificationCommand = "NoticeGatewayDRLNotification"
	NoticeGatewayLENotification  NotificationCommand = "NoticeGatewayLENotification"
	KeySpaceUpdateNotification   NotificationCommand = "KeySpaceUpdateNotification"
)

// Notification is a type that encodes a message published to a pub sub channel (shared between implementations)
type Notification struct {
	Command       NotificationCommand `json:"command"`
	Payload       string              `json:"payload"`
	Signature     string              `json:"signature"`
	SignatureAlgo crypto.Hash         `json:"algorithm"`
}

func (n *Notification) Sign() {
	n.SignatureAlgo = crypto.SHA256
	hash := sha256.Sum256([]byte(string(n.Command) + n.Payload + config.Global().NodeSecret))
	n.Signature = hex.EncodeToString(hash[:])
}

func startPubSubLoop() {
	cacheStore := storage.RedisCluster{}
	cacheStore.Connect()
	// On message, synchronise
	for {
		err := cacheStore.StartPubSubHandler(RedisPubSubChannel, func(v interface{}) {
			handleRedisEvent(v, nil, nil)
		})
		if err != nil {
			if err != storage.ErrRedisIsDown {
				pubSubLog.WithField("err", err).Error("Connection to Redis failed, reconnect in 10s")
			}
			time.Sleep(10 * time.Second)
			pubSubLog.Warning("Reconnecting ", err)
		}
	}
}

func handleRedisEvent(v interface{}, handled func(NotificationCommand), reloaded func()) {
	message, ok := v.(*redis.Message)
	if !ok {
		return
	}
	notif := Notification{}
	if err := json.Unmarshal([]byte(message.Payload), &notif); err != nil {
		pubSubLog.Error("Unmarshalling message body failed, malformed: ", err)
		return
	}

	// Add messages to ignore here
	switch notif.Command {
	case NoticeGatewayConfigResponse:
		return
	}

	// Check for a signature, if not signature found, handle
	if !isPayloadSignatureValid(notif) {
		pubSubLog.Error("Payload signature is invalid!")
		return
	}

	switch notif.Command {
	case NoticeDashboardZeroConf:
		handleDashboardZeroConfMessage(notif.Payload)
	case NoticeConfigUpdate:
		handleNewConfiguration(notif.Payload)
	case NoticeDashboardConfigRequest:
		handleSendMiniConfig(notif.Payload)
	case NoticeGatewayDRLNotification:
		if config.Global().ManagementNode {
			// DRL is not initialized, going through would
			// be mostly harmless but would flood the log
			// with warnings since DRLManager.Ready == false
			return
		}
		onServerStatusReceivedHandler(notif.Payload)
	case NoticeGatewayLENotification:
		onLESSLStatusReceivedHandler(notif.Payload)
	case NoticeApiUpdated, NoticeApiRemoved, NoticeApiAdded, NoticePolicyChanged, NoticeGroupReload:
		pubSubLog.Info("Reloading endpoints")
		reloadURLStructure(reloaded)
	case KeySpaceUpdateNotification:
		handleKeySpaceEventCacheFlush(notif.Payload)
	default:
		pubSubLog.Warnf("Unknown notification command: %q", notif.Command)
		return
	}
	if handled != nil {
		// went through. all others shoul have returned early.
		handled(notif.Command)
	}
}

func handleKeySpaceEventCacheFlush(payload string) {

	keys := strings.Split(payload, ",")

	for _, key := range keys {
		splitKeys := strings.Split(key, ":")
		if len(splitKeys) > 1 {
			key = splitKeys[0]
		}

		RPCGlobalCache.Delete("apikey-" + key)
		SessionCache.Delete(key)
	}
}

var redisInsecureWarn sync.Once
var notificationVerifier goverify.Verifier

func isPayloadSignatureValid(notification Notification) bool {
	if config.Global().AllowInsecureConfigs {
		return true
	}

	switch notification.SignatureAlgo {
	case crypto.SHA256:
		hash := sha256.Sum256([]byte(string(notification.Command) + notification.Payload + config.Global().NodeSecret))
		expectedSignature := hex.EncodeToString(hash[:])

		if expectedSignature == notification.Signature {
			return true
		} else {
			pubSubLog.Error("Notification signer: Failed verifying pub sub signature using node_secret: ")
			return false
		}
	default:
		if config.Global().PublicKeyPath != "" && notificationVerifier == nil {
			var err error

			notificationVerifier, err = goverify.LoadPublicKeyFromFile(config.Global().PublicKeyPath)
			if err != nil {

				pubSubLog.Error("Notification signer: Failed loading public key from path: ", err)
				return false
			}
		}

		if notificationVerifier != nil {

			signed, err := base64.StdEncoding.DecodeString(notification.Signature)
			if err != nil {

				pubSubLog.Error("Failed to decode signature: ", err)
				return false
			}

			if err := notificationVerifier.Verify([]byte(notification.Payload), signed); err != nil {

				pubSubLog.Error("Could not verify notification: ", err, ": ", notification)

				return false
			}

			return true
		}
	}

	return false
}

// RedisNotifier will use redis pub/sub channels to send notifications
type RedisNotifier struct {
	store   *storage.RedisCluster
	channel string
}

// Notify will send a notification to a channel
func (r *RedisNotifier) Notify(notif interface{}) bool {
	if n, ok := notif.(Notification); ok {
		n.Sign()
		notif = n
	}

	toSend, err := json.Marshal(notif)

	if err != nil {

		pubSubLog.Error("Problem marshalling notification: ", err)
		return false
	}

	// pubSubLog.Debug("Sending notification", notif)

	if err := r.store.Publish(r.channel, string(toSend)); err != nil {
		if err != storage.ErrRedisIsDown {
			pubSubLog.Error("Could not send notification: ", err)
		}
		return false
	}

	return true
}

type dashboardConfigPayload struct {
	DashboardConfig struct {
		Hostname string
		Port     int
		UseTLS   bool
	}
	TimeStamp int64
}

func createConnectionStringFromDashboardObject(config dashboardConfigPayload) string {

	hostname := "http://"

	if config.DashboardConfig.UseTLS {
		hostname = "https://"
	}

	hostname += config.DashboardConfig.Hostname

	if config.DashboardConfig.Port != 0 {

		hostname = strings.TrimRight(hostname, "/")
		hostname += ":" + strconv.Itoa(config.DashboardConfig.Port)
	}

	return hostname
}

func handleDashboardZeroConfMessage(payload string) {
	// Decode the configuration from the payload
	dashPayload := dashboardConfigPayload{}

	if err := json.Unmarshal([]byte(payload), &dashPayload); err != nil {

		pubSubLog.Error("Failed to decode dashboard zeroconf payload")
		return
	}

	globalConf := config.Global()

	if !globalConf.UseDBAppConfigs || globalConf.DisableDashboardZeroConf {
		return
	}

	hostname := createConnectionStringFromDashboardObject(dashPayload)
	setHostname := false

	if globalConf.DBAppConfOptions.ConnectionString == "" {
		globalConf.DBAppConfOptions.ConnectionString = hostname
		setHostname = true
	}

	if globalConf.Policies.PolicyConnectionString == "" {
		globalConf.Policies.PolicyConnectionString = hostname
		setHostname = true
	}

	if setHostname {
		config.SetGlobal(globalConf)
		pubSubLog.Info("Hostname set with dashboard zeroconf signal")
	}
}
