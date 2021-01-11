package subscription

import (
	"context"
)

type subscriptionCancellations map[string]context.CancelFunc

func (sc subscriptionCancellations) Add(id string) context.Context {
	ctx, cancelFunc := context.WithCancel(context.Background())
	sc[id] = cancelFunc
	return ctx
}

func (sc subscriptionCancellations) Cancel(id string) (ok bool) {
	cancelFunc, ok := sc[id]
	if !ok {
		return false
	}

	cancelFunc()
	delete(sc, id)
	return true
}

func (sc subscriptionCancellations) CancelAll() {
	for _, cancelFunc := range sc {
		cancelFunc()
	}
}
