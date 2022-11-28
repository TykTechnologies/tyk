package main

import (
	"bytes"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/Jeffail/tunny"
	"github.com/pmylund/go-cache"
)

const (
	defaultTimeout             int = 10
	defaultWorkerPoolSize      int = 50
	defaultSampletTriggerLimit int = 3
)

var HostCheckerClient *http.Client = &http.Client{Timeout: 500 * time.Millisecond}

type HostData struct {
	CheckURL string
	Method   string
	Headers  map[string]string
	Body     string
	MetaData map[string]string
}

type HostHealthReport struct {
	HostData
	ResponseCode int
	Latency      float64
	IsTCPError   bool
}

type HostUptimeChecker struct {
	failureCallback    func(HostHealthReport)
	upCallback         func(HostHealthReport)
	pingCallback       func(HostHealthReport)
	workerPoolSize     int
	sampleTriggerLimit int
	checkTimeout       int
	HostList           map[string]HostData
	unHealthyList      map[string]bool
	pool               *tunny.WorkPool

	errorChan       chan HostHealthReport
	okChan          chan HostHealthReport
	stopPollingChan chan bool
	sampleCache     *cache.Cache
	stopLoop        bool

	resetListMu sync.Mutex
	doResetList bool
	newList     *map[string]HostData
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

func (h *HostUptimeChecker) HostCheckLoop() {
	for {
		if h.stopLoop {
			break
		}
		h.resetListMu.Lock()
		if h.doResetList {
			if h.newList != nil {
				h.HostList = *h.newList
				h.newList = nil
				h.doResetList = false
				log.Debug("[HOST CHECKER] Host list reset")
			}
		}
		h.resetListMu.Unlock()
		for _, host := range h.HostList {
			_, err := h.pool.SendWork(host)
			if err != nil {
				log.Error("[HOST CHECKER] could not send work, error: %v", err)
			}
		}

		time.Sleep(h.getStaggeredTime())
	}
	log.Info("[HOST CHECKER] Checker stopped")
}

func (h *HostUptimeChecker) HostReporter() {
	for {
		select {
		case okHost := <-h.okChan:
			// Clear host from unhealthylist if it exists
			if h.unHealthyList[okHost.CheckURL] {
				h.upCallback(okHost)
				delete(h.unHealthyList, okHost.CheckURL)
			}
			go h.pingCallback(okHost)

		case failedHost := <-h.errorChan:
			newVal := 1
			if count, found := h.sampleCache.Get(failedHost.CheckURL); found {
				newVal = count.(int) + 1
			}

			h.sampleCache.Set(failedHost.CheckURL, newVal, cache.DefaultExpiration)

			if newVal >= h.sampleTriggerLimit {
				log.Debug("[HOST CHECKER] [HOST WARNING]: ", failedHost.CheckURL)
				// Reset the count
				h.sampleCache.Set(failedHost.CheckURL, 1, cache.DefaultExpiration)
				// track it
				h.unHealthyList[failedHost.CheckURL] = true
				// Call the custom callback hook
				go h.failureCallback(failedHost)
			}
			go h.pingCallback(failedHost)

		case <-h.stopPollingChan:
			log.Debug("[HOST CHECKER] Received kill signal")
			break
		}
	}
}

func (h *HostUptimeChecker) CheckHost(toCheck HostData) {
	log.Debug("[HOST CHECKER] Checking: ", toCheck.CheckURL)

	t1 := time.Now()

	var response *http.Response
	var respErr error

	useMethod := toCheck.Method
	if toCheck.Method == "" {
		useMethod = "GET"
	}

	var body = []byte(toCheck.Body)
	req, err := http.NewRequest(useMethod, toCheck.CheckURL, bytes.NewBuffer(body))
	if err != nil {
		log.Error("Could not create request: ", err)
		return
	}
	for header_name, header_value := range toCheck.Headers {
		req.Header.Set(header_name, header_value)
	}
	req.Header.Set("Connection", "close")

	response, respErr = HostCheckerClient.Do(req)

	t2 := time.Now()

	millisec := float64(t2.UnixNano()-t1.UnixNano()) * 0.000001

	report := HostHealthReport{
		HostData: toCheck,
		Latency:  millisec,
	}

	if respErr != nil {
		report.IsTCPError = true
		h.errorChan <- report
		return
	}

	report.ResponseCode = response.StatusCode

	if response.StatusCode != 200 {
		h.errorChan <- report
		return
	}

	// host is healthy, report it
	h.okChan <- report
}

func (h *HostUptimeChecker) Init(workers, triggerLimit, timeout int, hostList map[string]HostData, failureCallback func(HostHealthReport), upCallback func(HostHealthReport), pingCallback func(HostHealthReport)) {
	h.sampleCache = cache.New(30*time.Second, 5*time.Second)
	h.stopPollingChan = make(chan bool)
	h.errorChan = make(chan HostHealthReport)
	h.okChan = make(chan HostHealthReport)
	h.HostList = hostList
	h.unHealthyList = make(map[string]bool)
	h.failureCallback = failureCallback
	h.upCallback = upCallback
	h.pingCallback = pingCallback

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

	var pErr error
	h.pool, pErr = tunny.CreatePool(h.workerPoolSize, func(hostData interface{}) interface{} {
		input, _ := hostData.(HostData)
		h.CheckHost(input)
		return nil
	}).Open()

	log.Debug("[HOST CHECKER] Init complete")

	if pErr != nil {
		log.Error("[HOST CHECKER POOL] Error: %v\n", pErr)
	}
}

func (h *HostUptimeChecker) Start() {
	// Start the loop that checks for bum hosts
	h.stopLoop = false
	log.Debug("[HOST CHECKER] Starting...")
	go h.HostCheckLoop()
	log.Debug("[HOST CHECKER] Check loop started...")
	go h.HostReporter()
	log.Debug("[HOST CHECKER] Host reporter started...")
}

func (h *HostUptimeChecker) Stop() {
	h.stopLoop = true
	h.stopPollingChan <- true
	log.Info("[HOST CHECKER] Stopping poller")
	h.pool.Close()
}

func (h *HostUptimeChecker) RemoveHost(name string) {
	delete(h.HostList, name)
	log.Info("[HOST CHECKER] Stopped tracking: ", name)
}

func (h *HostUptimeChecker) ResetList(hostList *map[string]HostData) {
	h.resetListMu.Lock()
	h.doResetList = true
	h.newList = hostList
	h.resetListMu.Unlock()
	log.Debug("[HOST CHECKER] Checker reset queued!")
}

func hostcheck_example() {
	// Create the poller
	poller := &HostUptimeChecker{}
	poller.Init(defaultWorkerPoolSize,
		defaultSampletTriggerLimit,
		defaultTimeout,
		map[string]HostData{},
		// On failure
		func(fr HostHealthReport) {
			log.Error("This host is failing: ", fr.CheckURL)
			log.Info("---> Latency: \t", fr.Latency)
			if fr.IsTCPError {
				log.Info("---> TCP Error: \t", fr.IsTCPError)
			} else {
				log.Info("---> Response Code: \t", fr.ResponseCode)
			}

		},
		// On success
		func(fr HostHealthReport) {
			log.Info("Host is back up! URL: ", fr.CheckURL)
		},
		func(fr HostHealthReport) {
			log.Info("Host report, URL: ", fr.CheckURL)
		})

	// Start the check loop
	poller.Start()
	defer poller.Stop()

}
