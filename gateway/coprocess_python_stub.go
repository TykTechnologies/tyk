//go:build !cgo
// +build !cgo

// This only builds when CGO isn't enabled so that we don't attempt to do it on unsuiable environments,
// since CGO is required for Python plugins. Yet, we have to maintain symbol compatibility for the main package.
package gateway

import (
	"errors"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/coprocess"
)

var GatewayFireSystemEvent func(name apidef.TykEvent, meta interface{})

func NewPythonDispatcher(conf config.Config) (dispatcher coprocess.Dispatcher, err error) {
	return nil, errors.New("python support not compiled")
}
