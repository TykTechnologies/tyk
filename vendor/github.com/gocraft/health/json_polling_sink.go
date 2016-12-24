package health

import (
	"time"
)

type JsonPollingSink struct {
	intervalDuration  time.Duration
	cmdChan           chan *emitCmd
	doneChan          chan int
	doneDoneChan      chan int
	intervalsChanChan chan chan []*IntervalAggregation
}

type cmdKind int

const (
	cmdKindEvent cmdKind = iota
	cmdKindEventErr
	cmdKindTiming
	cmdKindGauge
	cmdKindComplete
)

type emitCmd struct {
	Kind   cmdKind
	Job    string
	Event  string
	Err    error
	Nanos  int64
	Value  float64
	Status CompletionStatus
}

func NewJsonPollingSink(intervalDuration time.Duration, retain time.Duration) *JsonPollingSink {
	const buffSize = 4096 // random-ass-guess

	s := &JsonPollingSink{
		intervalDuration:  intervalDuration,
		cmdChan:           make(chan *emitCmd, buffSize),
		doneChan:          make(chan int),
		doneDoneChan:      make(chan int),
		intervalsChanChan: make(chan chan []*IntervalAggregation),
	}

	go startAggregator(intervalDuration, retain, s)

	return s
}

func (s *JsonPollingSink) ShutdownServer() {
	s.doneChan <- 1
	<-s.doneDoneChan
}

func (s *JsonPollingSink) EmitEvent(job string, event string, kvs map[string]string) {
	s.cmdChan <- &emitCmd{Kind: cmdKindEvent, Job: job, Event: event}
}

func (s *JsonPollingSink) EmitEventErr(job string, event string, inputErr error, kvs map[string]string) {
	s.cmdChan <- &emitCmd{Kind: cmdKindEventErr, Job: job, Event: event, Err: inputErr}
}

func (s *JsonPollingSink) EmitTiming(job string, event string, nanos int64, kvs map[string]string) {
	s.cmdChan <- &emitCmd{Kind: cmdKindTiming, Job: job, Event: event, Nanos: nanos}
}

func (s *JsonPollingSink) EmitGauge(job string, event string, value float64, kvs map[string]string) {
	s.cmdChan <- &emitCmd{Kind: cmdKindGauge, Job: job, Event: event, Value: value}
}

func (s *JsonPollingSink) EmitComplete(job string, status CompletionStatus, nanos int64, kvs map[string]string) {
	s.cmdChan <- &emitCmd{Kind: cmdKindComplete, Job: job, Status: status, Nanos: nanos}
}

func (s *JsonPollingSink) GetMetrics() []*IntervalAggregation {
	intervalsChan := make(chan []*IntervalAggregation)
	s.intervalsChanChan <- intervalsChan
	return <-intervalsChan
}
