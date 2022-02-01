package graphqlerrors

type Location struct {
	Line   uint32 `json:"line"`
	Column uint32 `json:"column"`
}
