package gateway

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"strconv"
	"strings"
	"sync"
	"time"

	temporalmodel "github.com/TykTechnologies/storage/temporal/model"

	"github.com/TykTechnologies/tyk/internal/crypto"
	"github.com/TykTechnologies/tyk/storage"
)

type NotificationCommand string

func (n NotificationCommand) String() string {
	return string(n)
}

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
	KeySpaceUpdateNotification   NotificationCommand = "KeySpaceUpdateNotification"
	OAuthPurgeLapsedTokens       NotificationCommand = "OAuthPurgeLapsedTokens"
	// NoticeDeleteAPICache is the command with which event is emitted from dashboard to invalidate cache for an API.
	NoticeDeleteAPICache NotificationCommand = "DeleteAPICache"
)

// Notification is a type that encodes a message published to a pub sub channel (shared between implementations)
type Notification struct {
	Command       NotificationCommand `json:"command"`
	Payload       string              `json:"payload"`
	Signature     string              `json:"signature"`
	SignatureAlgo crypto.Hash         `json:"algorithm"`
	Gw            *Gateway            `json:"-"`
}

func (n *Notification) Sign() {
	n.SignatureAlgo = crypto.SHA256
	hash := sha256.Sum256([]byte(string(n.Command) + n.Payload + n.Gw.GetConfig().NodeSecret))
	n.Signature = hex.EncodeToString(hash[:])
}

func (gw *Gateway) startPubSubLoop() {
	cacheStore := storage.RedisCluster{ConnectionHandler: gw.StorageConnectionHandler}
	cacheStore.Connect()

	message := "Connection to Redis failed, reconnect in 10s"

	for {
		err := cacheStore.StartPubSubHandler(gw.ctx, RedisPubSubChannel, func(v interface{}) {
			gw.handleRedisEvent(v, nil, nil)
		})

		select {
		case <-gw.ctx.Done():
			pubSubLog.Info("Context cancelled, exiting pubsub loop")
			return
		default:
		}

		gw.logPubSubError(err, message)
		gw.addPubSubDelay(10 * time.Second)
	}
}

// addPubSubDelay sleeps for duration
func (gw *Gateway) addPubSubDelay(dur time.Duration) {
	time.Sleep(dur)
}

// isPubSubError returns true if err != nil, logs error
func (gw *Gateway) logPubSubError(err error, message string) bool {
	if err != nil {
		pubSubLog.WithError(err).Error(message)
		return true
	}
	return false
}

func (gw *Gateway) handleRedisEvent(v interface{}, handled func(NotificationCommand), reloaded func()) {
	message, ok := v.(temporalmodel.Message)
	if !ok {
		return
	}

	if message.Type() != temporalmodel.MessageTypeMessage {
		return
	}

	payload, err := message.Payload()
	if err != nil {
		pubSubLog.Error("Error getting payload from message: ", err)
		return
	}

	notif := Notification{Gw: gw}
	if err := json.Unmarshal([]byte(payload), &notif); err != nil {
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
		gw.handleDashboardZeroConfMessage(notif.Payload)
	case NoticeConfigUpdate:
		gw.handleNewConfiguration(notif.Payload)
	case NoticeDashboardConfigRequest:
		gw.handleSendMiniConfig(notif.Payload)
	case NoticeGatewayDRLNotification:
		if gw.GetConfig().ManagementNode {
			// DRL is not initialized, going through would
			// be mostly harmless but would flood the log
			// with warnings since DRLManager.Ready == false
			return
		}
		gw.onServerStatusReceivedHandler(notif.Payload)
	case NoticeApiUpdated:
		pubSubLog.Infof("Reloading API %s", notif.Payload)
		if notif.Payload != "" {
			gw.reloadSingleAPI(notif.Payload)
		} else {
			gw.reloadURLStructure(reloaded)
		}
	case NoticeApiRemoved, NoticeApiAdded, NoticePolicyChanged, NoticeGroupReload:
		pubSubLog.Info("Reloading endpoints")
		gw.reloadURLStructure(reloaded)
	case KeySpaceUpdateNotification:
		gw.handleKeySpaceEventCacheFlush(notif.Payload)
	case OAuthPurgeLapsedTokens:
		if err := gw.purgeLapsedOAuthTokens(); err != nil {
			log.WithError(err).Errorf("error while purging tokens for event %s", OAuthPurgeLapsedTokens)
		}
	case NoticeDeleteAPICache:
		if ok := gw.invalidateAPICache(notif.Payload); !ok {
			log.WithError(err).Errorf("cache invalidation failed for: %s", notif.Payload)
		}
	default:
		pubSubLog.Warnf("Unknown notification command: %q", notif.Command)
		return
	}
	if handled != nil {
		// went through. all others shoul have returned early.
		handled(notif.Command)
	}
}

func (gw *Gateway) handleKeySpaceEventCacheFlush(payload string) {

	keys := strings.Split(payload, ",")

	for _, key := range keys {
		splitKeys := strings.Split(key, ":")
		if len(splitKeys) > 1 {
			key = splitKeys[0]
		}

		gw.RPCGlobalCache.Delete("apikey-" + key)
		gw.SessionCache.Delete(key)
	}
}

var redisInsecureWarn sync.Once

func isPayloadSignatureValid(notification Notification) bool {
	if notification.Gw.GetConfig().AllowInsecureConfigs {
		return true
	}

	switch notification.SignatureAlgo {
	case crypto.SHA256:
		hash := sha256.Sum256([]byte(string(notification.Command) + notification.Payload + notification.Gw.GetConfig().NodeSecret))
		expectedSignature := hex.EncodeToString(hash[:])

		if expectedSignature == notification.Signature {
			return true
		} else {
			pubSubLog.Error("Notification signer: Failed verifying pub sub signature using node_secret: ")
			return false
		}
	default:
		verifier, err := notification.Gw.SignatureVerifier()
		if err != nil {
			pubSubLog.Error("Notification signer: Failed loading public key from path: ", err)
			return false
		}

		if verifier != nil {
			signed, err := base64.StdEncoding.DecodeString(notification.Signature)
			if err != nil {
				pubSubLog.Error("Failed to decode signature: ", err)
				return false
			}

			if err := verifier.Verify([]byte(notification.Payload), signed); err != nil {
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
	*Gateway
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
		if !errors.Is(err, storage.ErrRedisIsDown) {
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

func (gw *Gateway) handleDashboardZeroConfMessage(payload string) {
	// Decode the configuration from the payload
	dashPayload := dashboardConfigPayload{}

	if err := json.Unmarshal([]byte(payload), &dashPayload); err != nil {

		pubSubLog.Error("Failed to decode dashboard zeroconf payload")
		return
	}

	globalConf := gw.GetConfig()

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
		gw.SetConfig(globalConf)
		pubSubLog.Info("Hostname set with dashboard zeroconf signal")
	}
}
