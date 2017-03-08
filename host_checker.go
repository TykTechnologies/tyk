package main

import (
	"bytes"
	"math/rand"
	"net/http"
	"time"

	"github.com/jeffail/tunny"
	"github.com/pmylund/go-cache"
)

const (
	defaultTimeout             = 10
	defaultWorkerPoolSize      = 50
	defaultSampletTriggerLimit = 3
)

var HostCheckerClient = &http.Client{Timeout: 500 * time.Millisecond}

type HostData struct {
	CheckURL string
	ID       string
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
	checkTimout        int
	HostList           map[string]HostData
	unHealthyList      map[string]bool
	pool               *tunny.WorkPool

	errorChan       chan HostHealthReport
	okChan          chan HostHealthReport
	stopPollingChan chan bool
	sampleCache     *cache.Cache
	stopLoop        bool
	doResetList     bool
	newList         map[string]HostData
}

func (h *HostUptimeChecker) getStaggeredTime() time.Duration {
	if h.checkTimout <= 5 {
		return time.Duration(h.checkTimout) * time.Second
	}

	rand.Seed(time.Now().Unix())
	min := h.checkTimout - 3
	max := h.checkTimout + 3

	dur := rand.Intn(max-min) + min

	return time.Duration(dur) * time.Second
}

func (h *HostUptimeChecker) HostCheckLoop() {
	for !h.stopLoop {
		if h.doResetList {
			if h.newList != nil {
				h.HostList = h.newList
				h.newList = nil
				h.doResetList = false
				log.Debug("[HOST CHECKER] Host list reset")
			}
		}
		for _, host := range h.HostList {
			_, err := h.pool.SendWork(host)
			if err != nil {
				log.Errorf("[HOST CHECKER] could not send work, error: %v", err)
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
			if h.unHealthyList[okHost.ID] {
				h.upCallback(okHost)
				delete(h.unHealthyList, okHost.ID)
			}
			go h.pingCallback(okHost)

		case failedHost := <-h.errorChan:

			cachedHostCount, found := h.sampleCache.Get(failedHost.ID)
			if !found {
				go h.sampleCache.Set(failedHost.ID, 1, cache.DefaultExpiration)

			} else {
				newVal := cachedHostCount.(int)
				newVal++
				go h.sampleCache.Set(failedHost.ID, newVal, cache.DefaultExpiration)

				if newVal > h.sampleTriggerLimit {
					log.Debug("[HOST CHECKER] [HOST WARNING]: ", failedHost.CheckURL)
					// Reset the count
					go h.sampleCache.Set(failedHost.ID, 1, cache.DefaultExpiration)
					// track it
					h.unHealthyList[failedHost.ID] = true
					// Call the custom callback hook
					go h.failureCallback(failedHost)
				}
			}
			go h.pingCallback(failedHost)

		case <-h.stopPollingChan:
			log.Debug("[HOST CHECKER] Received kill signal")
			return
		}
	}
}

func (h *HostUptimeChecker) CheckHost(toCheck HostData) {
	log.Debug("[HOST CHECKER] Checking: ", toCheck.CheckURL, toCheck.ID)

	t1 := time.Now()

	useMethod := toCheck.Method
	if toCheck.Method == "" {
		useMethod = "GET"
	}

	body := []byte(toCheck.Body)
	req, err := http.NewRequest(useMethod, toCheck.CheckURL, bytes.NewBuffer(body))
	if err != nil {
		log.Error("Could not create request: ", err)
		return
	}
	for header_name, header_value := range toCheck.Headers {
		req.Header.Set(header_name, header_value)
	}
	req.Header.Set("Connection", "close")

	response, err := HostCheckerClient.Do(req)

	t2 := time.Now()

	millisec := float64(t2.UnixNano()-t1.UnixNano()) * 0.000001

	report := HostHealthReport{
		HostData: toCheck,
		Latency:  millisec,
	}

	if err != nil {
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

	h.checkTimout = timeout
	if timeout == 0 {
		h.checkTimout = defaultTimeout
	}

	log.Debug("[HOST CHECKER] Config:TriggerLimit: ", h.sampleTriggerLimit)
	log.Debug("[HOST CHECKER] Config:Timeout: ~", h.checkTimout)
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

func (h *HostUptimeChecker) ResetList(hostList map[string]HostData) {
	h.doResetList = true
	h.newList = hostList
	log.Debug("[HOST CHECKER] Checker reset queued!")
}
