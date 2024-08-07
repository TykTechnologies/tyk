package storage

import (
	"github.com/TykTechnologies/tyk/interfaces"
	"github.com/TykTechnologies/tyk/storage/mdcb"
	"github.com/sirupsen/logrus"
)

// MDCB Options
func WithLocalStorageHandler(handler interfaces.Handler) func(interfaces.Handler) {
	return func(impl interfaces.Handler) {
		// Type assertion for more iplementations later
		if impl, ok := impl.(*mdcb.MdcbStorage); ok {
			impl.Local = handler
		}
	}
}

func WithRpcStorageHandler(handler interfaces.Handler) func(interfaces.Handler) {
	return func(impl interfaces.Handler) {
		// Type assertion for more iplementations later
		if impl, ok := impl.(*mdcb.MdcbStorage); ok {
			impl.Rpc = handler
		}
	}
}

func WithLogger(logger *logrus.Entry) func(interfaces.Handler) {
	return func(impl interfaces.Handler) {
		// Type assertion for more iplementations later
		if impl, ok := impl.(*mdcb.MdcbStorage); ok {
			impl.Logger = logger
		}
	}
}
