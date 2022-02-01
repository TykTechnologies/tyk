//go:generate stringer -type=ValidationState -output validation_state_string.go

package astvalidation

// ValidationState is the outcome of a validation
type ValidationState int

const (
	UnknownState ValidationState = iota
	Valid
	Invalid
)
