package gateway

import (
	"context"
	"crypto/tls"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jeffail/tunny"
	proxyproto "github.com/pires/go-proxyproto"
	cache "github.com/pmylund/go-cache"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

const (
	defaultTimeout             = 10
	defaultWorkerPoolSize      = 50
	defaultSampletTriggerLimit = 3
)

var (
	HostCheckerClient = &http.Client{
		Timeout: 500 * time.Millisecond,
	}

	hostCheckTicker = make(chan struct{})
)

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

type HostUptimeChecker struct {
	cb                 HostCheckCallBacks
	workerPoolSize     int
	sampleTriggerLimit int
	checkTimeout       int
	HostList           map[string]HostData
	unHealthyList      map[string]bool
	pool               *tunny.WorkPool

	errorChan   chan HostHealthReport
	okChan      chan HostHealthReport
	sampleCache *cache.Cache
	stopLoop    bool
	muStopLoop  sync.RWMutex

	resetListMu sync.Mutex
	doResetList bool
	newList     map[string]HostData
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
	if isRunningTests() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hostCheckTicker:
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
		if err != nil {
			log.Errorf("[HOST CHECKER] could not send work, error: %v", err)
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
			// Clear host from unhealthylist if it exists
			if h.unHealthyList[okHost.CheckURL] {
				newVal := 1
				if count, found := h.sampleCache.Get(okHost.CheckURL); found {
					newVal = count.(int) - 1
				}

				if newVal <= 0 {
					// Reset the count
					h.sampleCache.Delete(okHost.CheckURL)
					log.Warning("[HOST CHECKER] [HOST UP]: ", okHost.CheckURL)
					if h.cb.Up != nil {
						go h.cb.Up(ctx, okHost)
					}
					delete(h.unHealthyList, okHost.CheckURL)
				} else {
					log.Warning("[HOST CHECKER] [HOST UP BUT NOT REACHED LIMIT]: ", okHost.CheckURL)
					h.sampleCache.Set(okHost.CheckURL, newVal, cache.DefaultExpiration)
				}
			}
			if h.cb.Ping != nil {
				go h.cb.Ping(ctx, okHost)
			}

		case failedHost := <-h.errorChan:
			newVal := 1
			if count, found := h.sampleCache.Get(failedHost.CheckURL); found {
				newVal = count.(int) + 1
			}

			if newVal >= h.sampleTriggerLimit {
				log.Warning("[HOST CHECKER] [HOST DOWN]: ", failedHost.CheckURL)
				// track it
				h.unHealthyList[failedHost.CheckURL] = true
				// Call the custom callback hook
				if h.cb.Fail != nil {
					go h.cb.Fail(ctx, failedHost)
				}
			} else {
				log.Warning("[HOST CHECKER] [HOST DOWN BUT NOT REACHED LIMIT]: ", failedHost.CheckURL)
				h.sampleCache.Set(failedHost.CheckURL, newVal, cache.DefaultExpiration)
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
		for headerName, headerValue := range toCheck.Headers {
			req.Header.Set(headerName, headerValue)
		}
		req.Header.Set("Connection", "close")
		HostCheckerClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.Global().ProxySSLInsecureSkipVerify,
			},
		}
		if toCheck.Timeout != 0 {
			HostCheckerClient.Timeout = toCheck.Timeout
		}
		response, err := HostCheckerClient.Do(req)
		if err != nil {
			report.IsTCPError = true
			break
		}
		response.Body.Close()
		report.ResponseCode = response.StatusCode
	}

	t2 := time.Now()

	millisec := float64(t2.UnixNano()-t1.UnixNano()) * 0.000001
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
	h.sampleCache = cache.New(30*time.Second, 30*time.Second)
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

func (h *HostUptimeChecker) Stop() {
	if !h.getStopLoop() {
		h.setStopLoop(true)
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
