package adapter

import "github.com/TykTechnologies/tyk/apidef"

type ImportAdapter interface {
	Import() (*apidef.APIDefinition, error)
}
