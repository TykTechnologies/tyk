package apidef

type (
	// SW-REQ-019
	HealthCheckStatus string

	// SW-REQ-019
	HealthCheckComponentType string
)

const (
	// SW-REQ-019
	Pass HealthCheckStatus = "pass"
	Fail                   = "fail"
	Warn                   = "warn"

	// SW-REQ-019
	Component HealthCheckComponentType = "component"
	Datastore                          = "datastore"
	System                             = "system"
)

// SW-REQ-019
type HealthCheckResponse struct {
	Status      HealthCheckStatus          `json:"status"`
	Version     string                     `json:"version,omitempty"`
	Output      string                     `json:"output,omitempty"`
	Description string                     `json:"description,omitempty"`
	Details     map[string]HealthCheckItem `json:"details,omitempty"`
}

// SW-REQ-019
type HealthCheckItem struct {
	Status        HealthCheckStatus `json:"status"`
	Output        string            `json:"output,omitempty"`
	ComponentType string            `json:"componentType,omitempty"`
	ComponentID   string            `json:"componentId,omitempty"`
	Time          string            `json:"time"`
}
