package gateway

import (
	"context"
	"crypto/tls"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Jeffail/tunny"
	proxyproto "github.com/pires/go-proxyproto"

	"github.com/TykTechnologies/tyk/apidef"
)

const (
	defaultTimeout             = 10
	defaultSampletTriggerLimit = 3
)

var defaultWorkerPoolSize = runtime.NumCPU()

type HostData struct {
	CheckURL            string
	Protocol            string
	Timeout             time.Duration
	EnableProxyProtocol bool
	Commands            []apidef.CheckCommand
	Method              string
	Headers             map[string]string
	Body                string
	MetaData            map[string]string
}

type HostHealthReport struct {
	HostData
	ResponseCode int
	Latency      float64
	IsTCPError   bool
}

type HostSample struct {
	count        int
	reachedLimit bool
}

type HostUptimeChecker struct {
	cb                 HostCheckCallBacks
	workerPoolSize     int
	sampleTriggerLimit int
	checkTimeout       int
	HostList           map[string]HostData
	unHealthyList      map[string]bool
	pool               *tunny.WorkPool

	errorChan  chan HostHealthReport
	okChan     chan HostHealthReport
	samples    *sync.Map
	stopLoop   bool
	muStopLoop sync.RWMutex

	resetListMu sync.Mutex
	doResetList bool
	newList     map[string]HostData
	Gw          *Gateway `json:"-"`
}

func (h *HostUptimeChecker) getStopLoop() bool {
	h.muStopLoop.RLock()
	defer h.muStopLoop.RUnlock()
	return h.stopLoop
}

func (h *HostUptimeChecker) setStopLoop(newValue bool) {
	h.muStopLoop.Lock()
	h.stopLoop = newValue
	h.muStopLoop.Unlock()
}

func (h *HostUptimeChecker) getStaggeredTime() time.Duration {
	if h.checkTimeout <= 5 {
		return time.Duration(h.checkTimeout) * time.Second
	}

	rand.Seed(time.Now().Unix())
	min := h.checkTimeout - 3
	max := h.checkTimeout + 3

	dur := rand.Intn(max-min) + min

	return time.Duration(dur) * time.Second
}

func (h *HostUptimeChecker) HostCheckLoop(ctx context.Context) {
	defer func() {
		log.Info("[HOST CHECKER] Checker stopped")
	}()
	if h.Gw.isRunningTests() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-h.Gw.HostCheckTicker:
				h.execCheck()
			}
		}
	} else {
		tick := time.NewTicker(h.getStaggeredTime())
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				h.execCheck()
			}
		}
	}
}

func (h *HostUptimeChecker) execCheck() {
	h.resetListMu.Lock()
	if h.doResetList && h.newList != nil {
		h.HostList = h.newList
		h.newList = nil
		h.doResetList = false
		log.Debug("[HOST CHECKER] Host list reset")
	}
	h.resetListMu.Unlock()
	for _, host := range h.HostList {
		_, err := h.pool.SendWork(host)
		if err != nil && err != tunny.ErrPoolNotRunning {
			log.Warnf("[HOST CHECKER] could not send work, error: %v", err)
		}
	}
}

func (h *HostUptimeChecker) HostReporter(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			if !h.getStopLoop() {
				h.Stop()
				log.Debug("[HOST CHECKER] Received cancel signal")
			}
			return
		case okHost := <-h.okChan:
			// check if the the host url is in the sample map
			if hostSample, found := h.samples.Load(okHost.CheckURL); found {
				sample := hostSample.(HostSample)
				//if it reached the h.sampleTriggerLimit, we're going to start decreasing the count value
				if sample.reachedLimit {
					newCount := sample.count - 1

					if newCount <= 0 {
						//if the count-1 is equals to zero, it means that the host is fully up.

						h.samples.Delete(okHost.CheckURL)
						log.Warning("[HOST CHECKER] [HOST UP]: ", okHost.CheckURL)
						go h.cb.Up(ctx, okHost)
					} else {
						//in another case, we are one step closer. We just update the count number
						sample.count = newCount
						log.Warning("[HOST CHECKER] [HOST UP BUT NOT REACHED LIMIT]: ", okHost.CheckURL)
						h.samples.Store(okHost.CheckURL, sample)
					}
				}
			}
			if h.cb.Ping != nil {
				go h.cb.Ping(ctx, okHost)
			}

		case failedHost := <-h.errorChan:
			sample := HostSample{
				count: 1,
			}

			//If a host fails, we check if it has failed already
			if hostSample, found := h.samples.Load(failedHost.CheckURL); found {
				sample = hostSample.(HostSample)
				// we add THIS failure to the count
				sample.count = sample.count + 1
			}

			if sample.count >= h.sampleTriggerLimit {
				// if it reached the h.sampleTriggerLimit, it means the host is down for us. We update the reachedLimit flag and store it in the sample map
				log.Warning("[HOST CHECKER] [HOST DOWN]: ", failedHost.CheckURL)

				//if this is the first time it reached the h.sampleTriggerLimit, the value of the reachedLimit flag is stored with the new count
				if sample.reachedLimit == false {
					sample.reachedLimit = true
					h.samples.Store(failedHost.CheckURL, sample)
				}

				//we call the failureCallback to keep the redis key and the host checker manager updated
				go h.cb.Fail(ctx, failedHost)

			} else {
				//if it failed but not reached the h.sampleTriggerLimit yet, we just add the counter to the map.
				log.Warning("[HOST CHECKER] [HOST DOWN BUT NOT REACHED LIMIT]: ", failedHost.CheckURL)
				h.samples.Store(failedHost.CheckURL, sample)
			}

			if h.cb.Ping != nil {
				go h.cb.Ping(ctx, failedHost)
			}
		}
	}
}

func (h *HostUptimeChecker) CheckHost(toCheck HostData) {
	log.Debug("[HOST CHECKER] Checking: ", toCheck.CheckURL)

	t1 := time.Now()
	report := HostHealthReport{
		HostData: toCheck,
	}
	switch toCheck.Protocol {
	case "tcp", "tls":
		host := toCheck.CheckURL
		base := toCheck.Protocol + "://"
		if !strings.HasPrefix(host, base) {
			host = base + host
		}
		u, err := url.Parse(host)
		if err != nil {
			log.Error("Could not parse host: ", err)
			return
		}
		var ls net.Conn
		var d net.Dialer
		d.Timeout = toCheck.Timeout
		if toCheck.Protocol == "tls" {
			ls, err = tls.DialWithDialer(&d, "tls", u.Host, nil)
		} else {
			ls, err = d.Dial("tcp", u.Host)
		}
		if err != nil {
			log.Error("Could not connect to host: ", err)
			report.IsTCPError = true
			break
		}
		if toCheck.EnableProxyProtocol {
			log.Debug("using proxy protocol")
			ls = proxyproto.NewConn(ls, 0)
		}
		defer ls.Close()
		for _, cmd := range toCheck.Commands {
			switch cmd.Name {
			case "send":
				log.Debugf("%s: sending %s", host, cmd.Message)
				_, err = ls.Write([]byte(cmd.Message))
				if err != nil {
					log.Errorf("Failed to send %s :%v", cmd.Message, err)
					report.IsTCPError = true
					break
				}
			case "expect":
				buf := make([]byte, len(cmd.Message))
				_, err = ls.Read(buf)
				if err != nil {
					log.Errorf("Failed to read %s :%v", cmd.Message, err)
					report.IsTCPError = true
					break
				}
				g := string(buf)
				if g != cmd.Message {
					log.Errorf("Failed expectation  expected %s got %s", cmd.Message, g)
					report.IsTCPError = true
					break
				}
				log.Debugf("%s: received %s", host, cmd.Message)
			}
		}
		report.ResponseCode = http.StatusOK
	default:
		useMethod := toCheck.Method
		if toCheck.Method == "" {
			useMethod = http.MethodGet
		}
		req, err := http.NewRequest(useMethod, toCheck.CheckURL, strings.NewReader(toCheck.Body))
		if err != nil {
			log.Error("Could not create request: ", err)
			return
		}
		ignoreCanonical := h.Gw.GetConfig().IgnoreCanonicalMIMEHeaderKey
		for headerName, headerValue := range toCheck.Headers {
			setCustomHeader(req.Header, headerName, headerValue, ignoreCanonical)
		}
		req.Header.Set("Connection", "close")
		h.Gw.HostCheckerClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: h.Gw.GetConfig().ProxySSLInsecureSkipVerify,
				MaxVersion:         h.Gw.GetConfig().ProxySSLMaxVersion,
			},
		}
		if toCheck.Timeout != 0 {
			h.Gw.HostCheckerClient.Timeout = toCheck.Timeout
		}
		response, err := h.Gw.HostCheckerClient.Do(req)
		if err != nil {
			report.IsTCPError = true
			break
		}
		response.Body.Close()
		report.ResponseCode = response.StatusCode
	}

	millisec := DurationToMillisecond(time.Since(t1))
	report.Latency = millisec
	if report.IsTCPError {
		h.errorChan <- report
		return
	}

	if report.ResponseCode != http.StatusOK {
		h.errorChan <- report
		return
	}

	// host is healthy, report it
	h.okChan <- report
}

// HostCheckCallBacks defines call backs which will be invoked on different
// states of the health check
type HostCheckCallBacks struct {
	// Up is a callback invoked when the host checker identifies a host to be up.
	Up func(context.Context, HostHealthReport)

	// Ping when provided this callback will be invoked on every every call to a
	// remote host.
	Ping func(context.Context, HostHealthReport)

	// Fail is invoked when the host checker decides a host is not healthy.
	Fail func(context.Context, HostHealthReport)
}

func (h *HostUptimeChecker) Init(workers, triggerLimit, timeout int, hostList map[string]HostData, cb HostCheckCallBacks) {
	h.samples = new(sync.Map)
	h.errorChan = make(chan HostHealthReport)
	h.okChan = make(chan HostHealthReport)
	h.HostList = hostList
	h.unHealthyList = make(map[string]bool)
	h.cb = cb

	h.workerPoolSize = workers
	if workers == 0 {
		h.workerPoolSize = defaultWorkerPoolSize
	}

	h.sampleTriggerLimit = triggerLimit
	if triggerLimit == 0 {
		h.sampleTriggerLimit = defaultSampletTriggerLimit
	}

	h.checkTimeout = timeout
	if timeout == 0 {
		h.checkTimeout = defaultTimeout
	}

	log.Debug("[HOST CHECKER] Config:TriggerLimit: ", h.sampleTriggerLimit)
	log.Debug("[HOST CHECKER] Config:Timeout: ~", h.checkTimeout)
	log.Debug("[HOST CHECKER] Config:WorkerPool: ", h.workerPoolSize)

	var err error
	h.pool, err = tunny.CreatePool(h.workerPoolSize, func(hostData interface{}) interface{} {
		input, _ := hostData.(HostData)
		h.CheckHost(input)
		return nil
	}).Open()

	log.Debug("[HOST CHECKER] Init complete")

	if err != nil {
		log.Errorf("[HOST CHECKER POOL] Error: %v\n", err)
	}
}

func (h *HostUptimeChecker) Start(ctx context.Context) {
	// Start the loop that checks for bum hosts
	h.setStopLoop(false)
	log.Debug("[HOST CHECKER] Starting...")
	go h.HostCheckLoop(ctx)
	log.Debug("[HOST CHECKER] Check loop started...")
	go h.HostReporter(ctx)
	log.Debug("[HOST CHECKER] Host reporter started...")
}

// eraseSyncMap uses native sync.Map functions to clear the map
// without needing to unsafely modify the value to nil.
func eraseSyncMap(m *sync.Map) {
	m.Range(func(k, _ interface{}) bool {
		m.Delete(k)
		return true
	})
}

func (h *HostUptimeChecker) Stop() {
	if !h.getStopLoop() {
		h.setStopLoop(true)

		eraseSyncMap(h.samples)

		log.Info("[HOST CHECKER] Stopping poller")
		h.pool.Close()
	}
}

func (h *HostUptimeChecker) ResetList(hostList map[string]HostData) {
	h.resetListMu.Lock()
	h.doResetList = true
	h.newList = hostList
	h.resetListMu.Unlock()
	log.Debug("[HOST CHECKER] Checker reset queued!")
}
