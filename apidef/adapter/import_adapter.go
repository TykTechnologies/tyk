package adapter

import "github.com/TykTechnologies/tyk/apidef"

// SW-REQ-068
type ImportAdapter interface {
	Import() (*apidef.APIDefinition, error)
}
