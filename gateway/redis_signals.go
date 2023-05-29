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

	"github.com/go-redis/redis/v8"

	"github.com/TykTechnologies/goverify"
	"github.com/TykTechnologies/tyk/storage"

	. "github.com/TykTechnologies/tyk/gateway/model"
)

func (gw *Gateway) startPubSubLoop() {
	cacheStore := storage.RedisCluster{RedisController: gw.RedisController}
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
	message, ok := v.(*redis.Message)
	if !ok {
		return
	}
	notif := Notification{Gw: gw}
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
	case NoticeApiUpdated, NoticeApiRemoved, NoticeApiAdded, NoticePolicyChanged, NoticeGroupReload:
		pubSubLog.Info("Reloading endpoints")
		gw.reloadURLStructure(reloaded)
	case KeySpaceUpdateNotification:
		gw.handleKeySpaceEventCacheFlush(notif.Payload)
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

func (gw *Gateway) GetNotificationVerifier(msg Notification) goverify.Verifier {
	if gw.NotificationVerifier != nil {
		return gw.NotificationVerifier
	}

	if msg.Gw.GetConfig().PublicKeyPath == "" {
		return nil
	}

	verifier, err := goverify.LoadPublicKeyFromFile(msg.Gw.GetConfig().PublicKeyPath)
	if err != nil {
		pubSubLog.WithError(err).Error("Notification signer: Failed loading public key from path")
		return nil
	}

	gw.NotificationVerifier = verifier
	return gw.NotificationVerifier
}

func isPayloadSignatureValid(msg Notification) bool {
	if msg.Gw.GetConfig().AllowInsecureConfigs {
		return true
	}

	switch msg.SignatureAlgo {
	case crypto.SHA256:
		hash := sha256.Sum256([]byte(string(msg.Command) + msg.Payload + msg.Gw.GetConfig().NodeSecret))
		expectedSignature := hex.EncodeToString(hash[:])

		if expectedSignature == msg.Signature {
			return true
		} else {
			pubSubLog.Error("Notification signer: Failed verifying pub sub signature using node_secret")
			return false
		}
	default:
		verifier := msg.Gw.GetNotificationVerifier(msg)
		if verifier != nil {
			signed, err := base64.StdEncoding.DecodeString(msg.Signature)
			if err != nil {
				pubSubLog.Error("Failed to decode signature: ", err)
				return false
			}

			if err := verifier.Verify([]byte(msg.Payload), signed); err != nil {
				pubSubLog.WithError(err).Error("Could not verify notification: ", msg)
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
