package state

import (
	"errors"
	"sync"
)

// StateChangeFunc defines the function signature for state change listeners.
type StateChangeFunc func(key, previous, current string)

// ErrNoListeners is the error returned when an attempt is made to set a state value without any listeners.
var ErrNoListeners = errors.New("no listeners have been added to the state engine")

// Engine represents the state management engine.
type Engine struct {
	state     sync.Map
	listeners []StateChangeFunc
}

// New initializes a new state engine.
func New() *Engine {
	return &Engine{}
}

// AddListener adds a state change listener to the engine.
func (e *Engine) AddListener(listener StateChangeFunc) {
	e.listeners = append(e.listeners, listener)
}

// Set updates the state for a given key and notifies the listeners of any change.
func (e *Engine) Set(key, current string) error {
	if len(e.listeners) == 0 {
		return ErrNoListeners
	}

	// Load the existing value, if present, and store the new one if different.
	previousValue, loaded := e.state.LoadOrStore(key, current)
	previous, ok := previousValue.(string)

	if loaded && ok && previous == current {
		// If the value has not changed, return without triggering listeners.
		return nil
	}

	e.state.Store(key, current)

	// Notify all listeners with the change.
	for _, listener := range e.listeners {
		listener(key, previous, current)
	}

	return nil
}
