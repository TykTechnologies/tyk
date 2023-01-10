package gateway

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/gorilla/mux"

	"github.com/TykTechnologies/tyk/apidef"
)

var (
	errVersionsNotFound = errors.New("no versions found for API")
)

type VersionMetas struct {
	Status string        `json:"status"`
	Metas  []VersionMeta `json:"apis"`
}

type VersionMeta struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	VersionName      string `json:"versionName"`
	Internal         bool   `json:"internal"`
	ExpirationDate   string `json:"expirationDate"`
	IsDefaultVersion bool   `json:"isDefaultVersion"`
}

type VersionsHandler struct {
	getApiDef func(string) (*apidef.APIDefinition, error)
}

func NewVersionHandler(getApiDef func(string) (*apidef.APIDefinition, error)) *VersionsHandler {
	return &VersionsHandler{getApiDef: getApiDef}
}

func (h *VersionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	apiID := mux.Vars(r)["apiID"]
	searchText := strings.ToLower(r.URL.Query().Get("searchText"))
	justInternal := r.URL.Query().Get("accessType") == "internal"
	justExternal := r.URL.Query().Get("accessType") == "external"

	canInclude := func(api *apidef.APIDefinition, name string) bool {
		if justInternal && !api.Internal {
			return false
		}

		if justExternal && api.Internal {
			return false
		}

		if searchText == "" {
			return true
		}

		return strings.Contains(strings.ToLower(name), searchText)
	}

	baseAPI, err := h.getApiDef(apiID)
	if err != nil {
		doJSONWrite(w, http.StatusNotFound, apiError(err.Error()))
		return
	}

	if len(baseAPI.VersionDefinition.Versions) == 0 {
		doJSONWrite(w, http.StatusNotFound, apiError(errVersionsNotFound.Error()))
		return
	}

	var (
		versionMetas VersionMetas
		baseAPIMeta  VersionMeta
	)

	if canInclude(baseAPI, baseAPI.VersionDefinition.Name) {
		baseAPIMeta = VersionMeta{
			ID:               baseAPI.APIID,
			Name:             baseAPI.Name,
			VersionName:      baseAPI.VersionDefinition.Name,
			Internal:         baseAPI.Internal,
			ExpirationDate:   baseAPI.Expiration,
			IsDefaultVersion: baseAPI.VersionDefinition.Default == baseAPI.VersionDefinition.Name,
		}
	}

	for name, id := range baseAPI.VersionDefinition.Versions {
		currentAPI, err := h.getApiDef(id)

		if err != nil {
			log.WithError(err).Errorf("Could not retrieve API version detail for id: %s", id)
			continue
		}

		if !canInclude(currentAPI, name) {
			continue
		}

		versionMetas.Metas = append(versionMetas.Metas, VersionMeta{
			ID:               id,
			Name:             currentAPI.Name,
			VersionName:      name,
			Internal:         currentAPI.Internal,
			ExpirationDate:   currentAPI.Expiration,
			IsDefaultVersion: baseAPI.VersionDefinition.Default == name,
		})
	}

	sort.Slice(versionMetas.Metas, func(i, j int) bool {
		return versionMetas.Metas[i].VersionName < versionMetas.Metas[j].VersionName
	})

	if baseAPIMeta.ID != "" {
		versionMetas.Metas = append([]VersionMeta{baseAPIMeta}, versionMetas.Metas...)
	}

	versionMetas.Status = "success"

	doJSONWrite(w, http.StatusOK, versionMetas)
}
