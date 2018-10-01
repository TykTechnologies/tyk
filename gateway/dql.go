package gateway

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/user"
)

const (
	defaultQuotaChunkSize          = 100
	defaultQuotaChunkReturnTimeout = 30
	defaultQuotaChunkReturnPart    = 0.2

	// we don't return chunk if less than that duration left until chunk expiration
	quotaChunkReturnGracePeriod = -300 * time.Millisecond

	quotaChunkRefundRequestInterval = 500 * time.Millisecond
)

// quota processing message
type quotaProcessingMsg struct {
	max         int64
	renewalRate int64
	replyCh     chan bool
}

type quotaChannels struct {
	processingCh         chan *quotaProcessingMsg // this channel receives requests while serving traffic to check if quota exceeded
	refundCh             chan bool                // this channel receives messages when some more busy server requests refund
	refundRequestChannel chan bool                // this channel is to send requests to other servers when current is ran out of quota
}

type quotaChunkRefundRequest struct {
	Key string
}

// DQL - Distributed Quota Limiter provides logic to use quotas distributed over several gateway instances
type DQL struct {
	thisServerID string

	thisServerLessLoaded   bool
	thisServerLessLoadedMu sync.Mutex

	store              storage.Handler
	chunkedQuotaConfig config.ChunkedQuotaConfig
	chunkReturnTimeout time.Duration

	channels   map[string]*quotaChannels // map of API key to set of related channels consumed by go-routine per key
	channelsMu sync.Mutex
}

// NewDQL creates new instance of distributed quota limiter
func NewDQL(store storage.Handler) *DQL {
	chunkedQuotaConfig := config.Global().ChunkedQuota
	if !chunkedQuotaConfig.EnableChunkedQuota {
		log.Error("Could not create distributed quota limiter because it is not enabled in config")
		return nil
	}

	// populate defaults if needed
	if chunkedQuotaConfig.ChunkSize == 0 {
		chunkedQuotaConfig.ChunkSize = defaultQuotaChunkSize
	}
	if chunkedQuotaConfig.ChunkReturnTimeout == 0 {
		chunkedQuotaConfig.ChunkReturnTimeout = defaultQuotaChunkReturnTimeout
	}
	if chunkedQuotaConfig.ChunkReturnPart <= 0 || chunkedQuotaConfig.ChunkReturnPart > 1 {
		chunkedQuotaConfig.ChunkReturnPart = defaultQuotaChunkReturnPart
	}

	return &DQL{
		thisServerID:       DRLManager.ThisServerID,
		store:              store,
		chunkedQuotaConfig: chunkedQuotaConfig,
		chunkReturnTimeout: time.Duration(chunkedQuotaConfig.ChunkReturnTimeout) * time.Second,
		channels:           make(map[string]*quotaChannels),
	}
}

func (d *DQL) getQuotaChannels(key string) *quotaChannels {
	d.channelsMu.Lock()
	defer d.channelsMu.Unlock()
	ch, ok := d.channels[key]
	if !ok {
		return nil
	}

	return ch
}

// IncrementAndCheck increments quota counter for the given session and returns true if quota is exceeded
func (d *DQL) IncrementAndCheck(session *user.SessionState) bool {
	key := QuotaKeyPrefix + session.KeyHash()

	// get key quota channels for the key
	d.channelsMu.Lock()
	ch, ok := d.channels[key] // one set of channels per API key
	if !ok {
		ch = &quotaChannels{
			processingCh:         make(chan *quotaProcessingMsg, d.chunkedQuotaConfig.ChunkSize),
			refundCh:             make(chan bool),
			refundRequestChannel: make(chan bool),
		}
		d.channels[key] = ch
		go d.quotaCounter(key, ch)                                   // one go routine per API key
		go d.quotaChunkRefundRequester(key, ch.refundRequestChannel) // again one go routine per API key
	}
	d.channelsMu.Unlock()

	// send message for quota processing
	replyCh := make(chan bool)
	ch.processingCh <- &quotaProcessingMsg{
		max:         session.QuotaMax,
		renewalRate: session.QuotaRenewalRate,
		replyCh:     replyCh,
	}

	// here we block to receive result - if quota exceeded for that session key or not
	return <-replyCh
}

func (d *DQL) quotaCounter(key string, ch *quotaChannels) {
	var chunk int64
	var chunkExpires time.Time
	var chunkNeverExpires bool
	var chunkTs time.Time
	for {
		select {
		case msg := <-ch.processingCh:
			// request new chunk if current chunk is 0 or expired
			if chunk == 0 || (!chunkNeverExpires && time.Now().After(chunkExpires)) {
				values, err := d.store.IncrementByWithExpire(key, d.chunkedQuotaConfig.ChunkSize, msg.renewalRate)
				if err != nil {
					log.WithError(err).Error("Could not request new quota chunk, just letting traffic go")
					msg.replyCh <- false
					continue
				}
				chunkTs = time.Now()
				total := values[0]
				if values[1] <= 0 { // no expiration
					chunkNeverExpires = true
				} else {
					chunkNeverExpires = false
					chunkExpires = chunkTs.Add(time.Duration(values[1]) * time.Second)
				}
				// check if we still need to allow some requests or reply that it was exceeded right away
				if total >= msg.max {
					if totalBefore := total - d.chunkedQuotaConfig.ChunkSize; totalBefore < msg.max {
						chunk = msg.max - totalBefore
					} else {
						// current chunk exceeded and no new chunks available
						chunk = 0
						msg.replyCh <- true
						// send request for refund to obtain some chunk maybe next time
						ch.refundRequestChannel <- true
						continue
					}
				} else {
					// new quota chunk received
					chunk = d.chunkedQuotaConfig.ChunkSize
				}
			}

			// decrement and allow request to proceed
			chunk--
			msg.replyCh <- false
		case <-ch.refundCh: // received signal to return part of chunk
			// check if this server is the less loaded
			if !d.canRefundOnRequest() {
				log.Debug("This server is not the slowest one, don't return part of chunk")
				continue
			}
			// refund part of current chunk if non zero and not expired and expiration is not too close
			if chunk > 0 && (chunkNeverExpires || time.Now().Before(chunkExpires.Add(quotaChunkReturnGracePeriod))) {
				returnPart := int64(float64(chunk) * d.chunkedQuotaConfig.ChunkReturnPart)
				if _, err := d.store.IncrementByWithExpire(key, -1*returnPart, 0); err != nil {
					log.WithError(err).Error("Could not return part of chunk")
				} else {
					chunk -= returnPart
				}
			}
		case <-time.After(d.chunkReturnTimeout): // wait, if no traffic for specified period - return chunk
			// return remain of current chunk if non zero and not expired and expiration is not too close
			if chunk > 0 && (chunkNeverExpires || time.Now().Before(chunkExpires.Add(quotaChunkReturnGracePeriod))) {
				if _, err := d.store.IncrementByWithExpire(key, -1*chunk, 0); err != nil {
					log.WithError(err).Error("Could not return chunk on timeout")
				} else {
					chunk = 0
				}
			} else {
				log.Debug("quota chunk was not returned")
			}
		}
	}
}

func (d *DQL) quotaChunkRefundRequester(key string, ch chan bool) {
	var lastSent time.Time
	for range ch {
		if time.Now().Before(lastSent.Add(quotaChunkRefundRequestInterval)) {
			continue
		}

		request := quotaChunkRefundRequest{Key: key}
		asJson, err := json.Marshal(request)
		if err != nil {
			log.WithError(err).Error("Failed to encode chunk refund request payload")
			continue
		}

		MainNotifier.Notify(
			Notification{
				Command: DQLChunkRefundRequestNotification,
				Payload: string(asJson),
			},
		)

		lastSent = time.Now()
	}
}

func (d *DQL) canRefundOnRequest() bool {
	d.thisServerLessLoadedMu.Lock()
	defer d.thisServerLessLoadedMu.Unlock()
	return d.thisServerLessLoaded
}

func (d *DQL) CheckServerLoad(serverID string, loadPerSec int64) {
	if serverID == d.thisServerID {
		return
	}

	d.thisServerLessLoadedMu.Lock()
	defer d.thisServerLessLoadedMu.Unlock()
	d.thisServerLessLoaded = GlobalRate.Rate() < loadPerSec
	if d.thisServerLessLoaded {
		log.Debug("this server is the less loaded one, distributed quota limiter will use this server to refund chunks")
	}
}

func onChunkRefundRequestReceivedHandler(payload string) {
	request := quotaChunkRefundRequest{}
	if err := json.Unmarshal([]byte(payload), &request); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).WithError(err).Error("Failed unmarshal chunk refund request data")
		return
	}

	log.Debug("Received quota chunk refund request: ", request)

	// get channel by key and send request for refund
	ch := DQLManager.getQuotaChannels(request.Key)
	if ch == nil {
		log.WithFields(logrus.Fields{
			"prefix": "pub-sub",
		}).Error("Failed to get refund channel for key to process chunk refund request data")
		return
	}

	ch.refundCh <- true
}
