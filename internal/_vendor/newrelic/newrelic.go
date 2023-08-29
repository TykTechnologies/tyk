package newrelic

import (
	agent "github.com/newrelic/go-agent"
)

type (
	Application = agent.Application
)

var (
	NewApplication = agent.NewApplication
	NewConfig      = agent.NewConfig
)
