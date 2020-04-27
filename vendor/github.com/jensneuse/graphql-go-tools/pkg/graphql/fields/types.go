package fields

type (
	Type struct {
		Name   string   `json:"name"`
		Fields []string `json:"fields"`
	}

	RequestFields map[string]struct{}
	RequestTypes  map[string]RequestFields
)
