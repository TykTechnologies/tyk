package main

import (
	"net/http"
	"plugin"

	"github.com/pkg/errors"

	"github.com/TykTechnologies/tyk/apidef"
	nativePlugin "github.com/TykTechnologies/tyk/plugin"
)

// TransformMiddleware is a middleware that will apply a template to a request body to transform it's contents ready for an upstream API
type PrePlugin struct {
	BaseMiddleware
	Executor nativePlugin.Executor
}

func (t *PrePlugin) Name() string {
	return "PrePlugin"
}

func (t *PrePlugin) EnabledForSpec() bool {
	for _, version := range t.Spec.VersionData.Versions {
		if len(version.ExtendedPaths.PrePlugin) == 0 {
			return false
		}

		for _, p := range version.ExtendedPaths.PrePlugin {
			plug, err := plugin.Open(p.Plugin)
			if err != nil {
				log.WithError(err).Fatal("unable to open plugin")
			}

			pluginSymbol, err := plug.Lookup(p.Fn)
			if err != nil {
				log.WithError(err).Fatal("unable to lookup plugin")
			}

			executor, ok := pluginSymbol.(nativePlugin.Executor)
			if !ok {
				log.WithError(err).Fatal("plugin symbol not of executor type")
			}

			t.Executor = executor
		}

		return true
	}
	return false
}

// ProcessRequest will run any checks on the request on the way through the system, return an error to have the chain fail
func (t *PrePlugin) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {

	_, versionPaths, _, _ := t.Spec.Version(r)
	found, meta := t.Spec.CheckSpecMatchesStatus(r, versionPaths, PrePluginRequest)
	if !found {
		return nil, http.StatusOK
	}

	_, ok := meta.(*apidef.PrePluginMeta)
	if !ok {
		return errors.New("not of type PrePluginMeta"), http.StatusInternalServerError
	}

	if err := t.Executor.Do(r); err != nil {
		return errors.Wrap(err, "unable to execute function"), http.StatusInternalServerError
	}

	return nil, http.StatusOK
}
