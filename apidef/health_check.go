package apidef

type (
	HealthCheckStatus string

	HealthCheckComponentType string
)

const (
	Pass HealthCheckStatus = "pass"
	Fail                   = "fail"
	Warn                   = "warn"

	Component HealthCheckComponentType = "component"
	Datastore                          = "datastore"
	System                             = "system"
)

type HealthCheckResponse struct {
	Status      HealthCheckStatus          `json:"status" enum:"pass,fail,warn"`
	Version     string                     `json:"version,omitempty"`
	Output      string                     `json:"output,omitempty"`
	Description string                     `json:"description,omitempty"`
	Details     map[string]HealthCheckItem `json:"details,omitempty"`
}

type HealthCheckItem struct {
	Status        HealthCheckStatus `json:"status" enum:"pass,fail,warn"`
	Output        string            `json:"output,omitempty"`
	ComponentType string            `json:"componentType,omitempty"`
	ComponentID   string            `json:"componentId,omitempty"`
	Time          string            `json:"time"`
}
