package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gernest/notify"
	"google.golang.org/grpc"
)

func main() {
	port := flag.Int("port", 9000, "listening port")
	ls, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatal("Failed to start listener", err)
	}
	defer ls.Close()
	svr := grpc.NewServer()
	s := &server{
		subscribers: make(map[string]*sync.Map),
		accept:      make(chan *accept, 100),
	}
	go s.notify()
	notify.RegisterPubSubServer(svr, s)
	i("Listening on ", ls.Addr())
	if err := svr.Serve(ls); err != nil {
		log.Fatal("exited  grpc server", err)
	}
}

var _ notify.PubSubServer = (*server)(nil)

type server struct {
	notify.UnimplementedPubSubServer
	subscribers map[string]*sync.Map
	accept      chan *accept
	mu          sync.RWMutex
}

type notice struct {
	id  int
	out chan *notify.Message
}

type accept struct {
	channel string
	message string
}

var id int64

func newID() int64 {
	return atomic.AddInt64(&id, 1)
}

func (p *server) Subscribe(in *notify.SubscribeRequest, a notify.PubSub_SubscribeServer) error {
	i("creating subscription ", in.Channel)
	stream := make(chan *notify.Message)
	pubID := newID()
	p.mu.Lock()
	s, ok := p.subscribers[in.Channel]
	if !ok {
		s = new(sync.Map)
		p.subscribers[in.Channel] = s
	}
	s.Store(pubID, stream)
	p.mu.Unlock()
	defer p.release(in.Channel, pubID)
	for msg := range stream {
		err := a.Send(msg)
		if err != nil {
			e(in.Channel, err)
			return err
		}
	}
	return nil
}

func (p *server) notify() {
	i("start watching for publishes")
	for {
		select {
		case e := <-p.accept:
			i("received publication request for channel ", e.channel)
			p.mu.RLock()
			s, ok := p.subscribers[e.channel]
			p.mu.RUnlock()
			if ok {
				send(s, e)
			}
		}
	}
}

func send(s *sync.Map, e *accept) {
	s.Range(func(key, value interface{}) bool {
		go try(e.channel, key.(int64), value.(chan *notify.Message), e.message)
		return true
	})
}

func try(channel string, id int64, ch chan *notify.Message, msg string) {
	i("sending publish message to ", id)
	ts := time.NewTimer(time.Second)
	defer ts.Stop()
	select {
	case ch <- &notify.Message{
		Channel: channel,
		Payload: msg,
	}:
		i("successful sent message to ", id)
	case <-ts.C:
		e("timeout publishing message to", id)
	}
}
func (p *server) release(channel string, id int64) {
	p.mu.RLock()
	defer p.mu.RLock()
	if s, ok := p.subscribers[channel]; ok {
		s.Delete(id)
	}
}

func i(v ...interface{}) {
	log.Printf("INFO %v\n", fmt.Sprint(v...))
}

func e(v ...interface{}) {
	log.Printf("ERROR %v\n", fmt.Sprint(v...))
}

func (p *server) Publish(ctx context.Context, in *notify.PublishRequest) (*notify.PublishResponse, error) {
	p.accept <- &accept{
		channel: in.Channel,
		message: in.Message,
	}
	return &notify.PublishResponse{}, nil
}
