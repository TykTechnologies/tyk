package apidef

import (
	"fmt"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/common/option"
	"net/http"
)

const (
	BaseAPIID VersionParameter = iota
	BaseAPIVersionName
	NewVersionName
	SetDefault
	paramCount
)

type VersionParameter int

func (v VersionParameter) String() string {
	return []string{"base_api_id", "base_api_version_name", "new_version_name", "setDefault"}[v]
}

func AllVersionParameters() []VersionParameter {
	params := make([]VersionParameter, paramCount)
	for i := range params {
		params[i] = VersionParameter(i)
	}

	return params
}

type VersionQueryParameters struct {
	versionParams map[string]string
}

func (v *VersionQueryParameters) Validate(doesBaseApiExists func() (bool, string)) error {
	baseID := v.versionParams[BaseAPIID.String()]
	if baseID == "" {
		return nil
	}

	exists, baseName := doesBaseApiExists()
	if !exists {
		return fmt.Errorf("%s is not a valid Base API version", baseID)
	}

	if v.versionParams[BaseAPIVersionName.String()] == "" && baseName == "" {
		return fmt.Errorf("you need to provide a version name for the new Base API: %s", baseID)
	}

	return nil
}

func (v *VersionQueryParameters) IsEmpty(param VersionParameter) bool {
	return v.versionParams[param.String()] == ""
}

func (v *VersionQueryParameters) Get(param VersionParameter) string {
	return v.versionParams[param.String()]
}

func NewVersionQueryParameters(req *http.Request) *VersionQueryParameters {
	versionParams := &VersionQueryParameters{
		versionParams: make(map[string]string, paramCount),
	}

	for _, param := range AllVersionParameters() {
		paramName := param.String()
		versionParams.versionParams[paramName] = req.URL.Query().Get(paramName)
	}

	return versionParams
}

// WithVersionName sets the version name
func WithVersionName(name string) option.Option[apidef.VersionDefinition] {
	return func(version *apidef.VersionDefinition) {
		version.Name = name
	}
}

// AddVersion adds a version mapping
func AddVersion(versionName, apiID string) option.Option[apidef.VersionDefinition] {
	return func(vd *apidef.VersionDefinition) {
		vd.Versions[versionName] = apiID
	}
}

// SetAsDefault marks a version as the default
func SetAsDefault(versionName string) option.Option[apidef.VersionDefinition] {
	return func(vd *apidef.VersionDefinition) {
		vd.Default = versionName
	}
}

// ConfigureVersionDefinition sets up the version definition with default values if not already set
func ConfigureVersionDefinition(def apidef.VersionDefinition, params *VersionQueryParameters, apiID string) *apidef.VersionDefinition {
	opts := make([]option.Option[apidef.VersionDefinition], 0)

	def.Enabled = true

	if !params.IsEmpty(BaseAPIVersionName) {
		opts = append(opts, WithVersionName(params.versionParams[BaseAPIVersionName.String()]))
	}

	if !params.IsEmpty(SetDefault) {
		setDefault := params.versionParams[SetDefault.String()]
		if setDefault == "true" {
			opts = append(opts, SetAsDefault(params.versionParams[NewVersionName.String()]))
		}
	}

	opts = append(opts, AddVersion(params.versionParams[NewVersionName.String()], apiID))

	if def.Key == "" {
		def.Key = apidef.DefaultAPIVersionKey
	}

	if def.Location == "" {
		def.Location = apidef.HeaderLocation
	}

	if def.Default == "" {
		def.Default = apidef.Self
	}

	if def.Versions == nil {
		def.Versions = make(map[string]string)
	}

	return option.New(opts).Build(def)
}
