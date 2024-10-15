package policy

import "github.com/TykTechnologies/tyk/gateway"

const DefaultOrg = "default-org-id"

type (
	Gateway        = gateway.Gateway
	APISpec        = gateway.APISpec
	BaseMiddleware = gateway.BaseMiddleware
)

var StartTest = gateway.StartTest
