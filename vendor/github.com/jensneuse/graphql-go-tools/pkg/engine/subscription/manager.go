package subscription

import (
	"github.com/jensneuse/graphql-go-tools/pkg/pool"
)

func NewManager(stream Stream) *Manager {
	return &Manager{
		stream:             stream,
		subscribers:        map[uint64]int64{},
		subscriptions:      map[uint64]*subscription{},
		addTrigger:         make(chan addTrigger),
		removeTrigger:      make(chan Trigger),
		countSubscribers:   make(chan chan int64),
		countSubscriptions: make(chan chan int64),
	}
}

type addTrigger struct {
	trigger Trigger
	input   []byte
}

type Manager struct {
	stream             Stream
	subscriptions      map[uint64]*subscription
	subscribers        map[uint64]int64
	addTrigger         chan addTrigger
	removeTrigger      chan Trigger
	countSubscriptions chan chan int64
	countSubscribers   chan chan int64
}

func (m *Manager) TotalSubscriptions() int64 {
	out := make(chan int64)
	m.countSubscriptions <- out
	return <-out
}

func (m *Manager) TotalSubscribers() int64 {
	out := make(chan int64)
	m.countSubscribers <- out
	return <-out
}

func (m *Manager) Run(done <-chan struct{}) {
	go m.run(done)
}

func (m *Manager) run(done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case addTrigger := <-m.addTrigger:
			sub, exists := m.subscriptions[addTrigger.trigger.subscriptionID]
			if !exists {
				sub = &subscription{
					triggers: map[Trigger]struct{}{
						addTrigger.trigger: {},
					},
					addTrigger:    make(chan Trigger),
					removeTrigger: make(chan Trigger),
					stop:          make(chan struct{}),
					results:       make(chan []byte),
				}
				m.subscriptions[addTrigger.trigger.subscriptionID] = sub
				m.subscribers[addTrigger.trigger.subscriptionID] = 1
				go m.stream.Start(addTrigger.input, sub.results, sub.stop)
				go sub.run()
				continue
			}
			sub.addTrigger <- addTrigger.trigger
			m.subscribers[addTrigger.trigger.subscriptionID] += 1
		case trigger := <-m.removeTrigger:
			m.subscriptions[trigger.subscriptionID].removeTrigger <- trigger
			subscribers := m.subscribers[trigger.subscriptionID] - 1
			if subscribers == 0 {
				close(m.subscriptions[trigger.subscriptionID].stop)
				delete(m.subscriptions, trigger.subscriptionID)
				delete(m.subscribers, trigger.subscriptionID)
				continue
			}
			m.subscribers[trigger.subscriptionID] = subscribers
		case out := <-m.countSubscriptions:
			out <- int64(len(m.subscriptions))
		case out := <-m.countSubscribers:
			var subs int64
			for i := range m.subscribers {
				subs += m.subscribers[i]
			}
			out <- subs
		}
	}
}

type subscription struct {
	triggers      map[Trigger]struct{}
	addTrigger    chan Trigger
	removeTrigger chan Trigger
	stop          chan struct{}
	results       chan []byte
}

func (s *subscription) run() {
	for {
		select {
		case <-s.stop:
			return
		case trigger := <-s.addTrigger:
			s.triggers[trigger] = struct{}{}
		case trigger := <-s.removeTrigger:
			delete(s.triggers, trigger)
		case result := <-s.results:
			for trigger := range s.triggers {
				trigger.results <- result
			}
		}
	}
}

func (m *Manager) StartTrigger(input []byte) (trigger Trigger) {
	subscriptionID := m.subscriptionID(input)
	trigger = NewTrigger(subscriptionID)
	m.addTrigger <- addTrigger{
		trigger: trigger,
		input:   input,
	}
	return
}

func (m *Manager) StopTrigger(trigger Trigger) {
	m.removeTrigger <- trigger
}

func (m *Manager) subscriptionID(input []byte) uint64 {
	hash64 := pool.Hash64.Get()
	_, _ = hash64.Write(input)
	subscriptionID := hash64.Sum64()
	pool.Hash64.Put(hash64)
	return subscriptionID
}

func (m *Manager) UniqueIdentifier() []byte {
	return m.stream.UniqueIdentifier()
}
