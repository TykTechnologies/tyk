package gateway

import (
	"github.com/sirupsen/logrus"
	"path/filepath"
)

// reloadSingleAPI reloads only the API with the given id.
// It falls back to a full reload if the definition cannot be loaded.
func (gw *Gateway) reloadSingleAPI(id string) {
	loader := APIDefinitionLoader{Gw: gw}
	path := filepath.Join(gw.GetConfig().AppPath, id+".json")
	spec, err := loader.loadDefFromFilePath(path)
	if err != nil {
		log.WithError(err).Warn("single reload failed, falling back to full reload")
		gw.reloadURLStructure(nil)
		return
	}

	gw.apisMu.Lock()
	replaced := false
	for i, s := range gw.apiSpecs {
		if s.APIID == id {
			gw.apiSpecs[i] = spec
			replaced = true
			break
		}
	}
	if !replaced {
		gw.apiSpecs = append(gw.apiSpecs, spec)
	}
	gw.apisByID[id] = spec
	gw.apisMu.Unlock()

	gs := gw.prepareStorage()
	apisByListen := countApisByListenHash(gw.apiSpecs)
	chain := gw.loadHTTPService(spec, apisByListen, &gs, gw.DefaultProxyMux)
	if chain != nil {
		gw.apisHandlesByID.Store(id, chain)
	}
}