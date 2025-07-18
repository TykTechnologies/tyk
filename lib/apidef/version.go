package apidef

import (
	"errors"
	"fmt"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/common/option"
	"net/url"
)

const (
	BaseAPIID VersionParameter = iota
	BaseAPIVersionName
	NewVersionName
	SetDefault
	paramCount
)

var (
	ErrNewVersionRequired = errors.New("The new version name is required")
)

// VersionParameter represents the type of parameter used in API version configuration.
// It defines the possible parameters that can be used when working with API versions.
type VersionParameter int

// String returns the string representation of a VersionParameter.
// It converts the numeric parameter value to its corresponding string identifier.
func (v VersionParameter) String() string {
	return []string{"base_api_id", "base_api_version_name", "new_version_name", "set_default"}[v]
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
	if v.IsEmpty(BaseAPIID) {
		return nil
	}
	baseID := v.Get(BaseAPIID)

	if v.IsEmpty(NewVersionName) {
		return ErrNewVersionRequired
	}

	exists, baseName := doesBaseApiExists()
	if !exists {
		return fmt.Errorf("%s is not a valid Base API version", baseID)
	}

	if v.IsEmpty(BaseAPIVersionName) && baseName == "" {
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
func NewVersionQueryParameters(query url.Values) *VersionQueryParameters {
	versionParams := &VersionQueryParameters{
		versionParams: make(map[string]string, paramCount),
	}

	for _, param := range AllVersionParameters() {
		paramName := param.String()
		versionParams.versionParams[paramName] = query.Get(paramName)
	}

	return versionParams
}

// WithVersionName creates an option that sets the version name in a VersionDefinition.
func WithVersionName(name string) option.Option[apidef.VersionDefinition] {
	return func(version *apidef.VersionDefinition) {
		version.Name = name
	}
}

// WithBaseID creates an option that sets the version baseID in a VersionDefinition.
func WithBaseID(id string) option.Option[apidef.VersionDefinition] {
	return func(version *apidef.VersionDefinition) {
		version.BaseID = id
	}
}

// AddVersion creates an option that adds a version mapping to a VersionDefinition.
// It associates a version name with an API ID in the Versions map.
func AddVersion(versionName, apiID string) option.Option[apidef.VersionDefinition] {
	return func(vd *apidef.VersionDefinition) {
		vd.Versions[versionName] = apiID
	}
}

// SetAsDefault creates an option that marks a specific version as the default.
// This sets the Default field in the VersionDefinition to the specified version name.
func SetAsDefault(versionName string) option.Option[apidef.VersionDefinition] {
	return func(vd *apidef.VersionDefinition) {
		vd.Default = versionName
	}
}

// ConfigureVersionDefinition sets up the version definition with default values if not already set.
// It applies the provided parameters to configure the version definition and ensures
// that required fields have appropriate values.
func ConfigureVersionDefinition(def apidef.VersionDefinition, params *VersionQueryParameters, newApiID string) apidef.VersionDefinition {
	opts := make([]option.Option[apidef.VersionDefinition], 0)

	if !params.IsEmpty(BaseAPIID) {
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

		if !params.IsEmpty(BaseAPIID) {
			opts = append(opts, WithBaseID(params.versionParams[BaseAPIID.String()]))
		}

		opts = append(opts, AddVersion(params.versionParams[NewVersionName.String()], newApiID))
	}

	// When baseAPIID is missing in the request params, and it's versioning is enabled then set versioning ID as APIID
	if params.IsEmpty(BaseAPIID) && def.BaseID == "" {
		def.BaseID = newApiID
	}

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

	return *option.New(opts).Build(def)
}
