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

// VersionParameter represents the type of parameter used in API version configuration.
// It defines the possible parameters that can be used when working with API versions.
type VersionParameter int

// String returns the string representation of a VersionParameter.
// It converts the numeric parameter value to its corresponding string identifier.
func (v VersionParameter) String() string {
	return []string{"base_api_id", "base_api_version_name", "new_version_name", "setDefault"}[v]
}

// AllVersionParameters returns a slice containing all available version parameters.
// This is useful for iterating through all possible version parameters.
func AllVersionParameters() []VersionParameter {
	params := make([]VersionParameter, paramCount)
	for i := range params {
		params[i] = VersionParameter(i)
	}

	return params
}

// VersionQueryParameters holds the version-related parameters extracted from HTTP requests.
// It provides methods to access and validate these parameters.
type VersionQueryParameters struct {
	versionParams map[string]string
}

// Validate checks if the version parameters are valid.
// It takes a function that checks if the base API exists and returns an error if validation fails.
// The doesBaseApiExists function should return whether the base API exists and its name.
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

// IsEmpty checks if a specific version parameter is empty or not set.
// Returns true if the parameter is empty, false otherwise.
func (v *VersionQueryParameters) IsEmpty(param VersionParameter) bool {
	return v.versionParams[param.String()] == ""
}

// Get retrieves the value of a specific version parameter.
// Returns the string value of the parameter.
func (v *VersionQueryParameters) Get(param VersionParameter) string {
	return v.versionParams[param.String()]
}

// NewVersionQueryParameters creates a new VersionQueryParameters instance from an HTTP request.
// It extracts all version-related parameters from the request's URL query.
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
