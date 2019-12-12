// +build !cgo

// This only builds when CGO isn't enabled so that we don't attempt to do it on unsuiable environments,
// since CGO is required for Python plugins. Yet, we have to maintain symbol compatibility for the main package.
package gateway

import (
	"errors"

	"github.com/TykTechnologies/tyk/coprocess"
)

func NewPythonDispatcher() (dispatcher coprocess.Dispatcher, err error) {
	return nil, errors.New("python support not compiled")
}
