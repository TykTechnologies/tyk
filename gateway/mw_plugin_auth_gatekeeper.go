package gateway

import (
	"errors"
	"net/http"
)

const (
	disallowedAccessErrorMsg = "access to this API has been disallowed due to invalid configuration of Custom Plugin Authentication"
)

type PluginAuthGatekeeperMiddleware struct {
	*BaseMiddleware
}

func (p *PluginAuthGatekeeperMiddleware) Name() string {
	return "PluginAuthGatekeeperMiddleware"
}

func (p *PluginAuthGatekeeperMiddleware) EnabledForSpec() bool {
	customPluginAuthEnabled := p.Spec.CustomPluginAuthEnabled || p.Spec.UseGoPluginAuth || p.Spec.EnableCoProcessAuth

	return customPluginAuthEnabled && (p.Spec.CustomMiddleware.Driver == "" || p.Spec.CustomMiddleware.AuthCheck.Path == "")
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (p *PluginAuthGatekeeperMiddleware) ProcessRequest(_ http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	AuthFailed(p, r, "")
	return errors.New(disallowedAccessErrorMsg), http.StatusForbidden
}
