package subscription

import (
	"sync"
	"time"
)

func NewStreamStub(uniqueIdentifier []byte, done <-chan struct{}) *StreamStub {
	return &StreamStub{
		uniqueIdentifier: uniqueIdentifier,
		done:             done,

		mu:          &sync.Mutex{},
		messagePipe: make(map[string]chan []byte),
	}
}

type StreamStub struct {
	uniqueIdentifier []byte
	done             <-chan struct{}

	mu          *sync.Mutex
	messagePipe map[string]chan []byte
}

func (f *StreamStub) SendMessage(to string, message []byte) {
	f.mu.Lock()
	ch, ok := f.messagePipe[to]
	if !ok {
		ch = make(chan []byte)
		f.messagePipe[to] = ch
	}
	f.mu.Unlock()
	ch <- message
}

func (f *StreamStub) Start(input []byte, next chan<- []byte, stop <-chan struct{}) {
	f.mu.Lock()
	ch, ok := f.messagePipe[string(input)]
	if !ok {
		ch = make(chan []byte)
		f.messagePipe[string(input)] = ch
	}
	f.mu.Unlock()

	for {
		time.Sleep(time.Millisecond)
		select {
		case <-stop:
			return
		case <-f.done:
			return
		case mes := <-ch:
			next <- mes
		}
	}
}

func (f *StreamStub) UniqueIdentifier() []byte {
	return f.uniqueIdentifier
}
