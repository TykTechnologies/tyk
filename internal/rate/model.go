package rate

import (
	"github.com/TykTechnologies/tyk/internal/rate/model"
)

// SW-REQ-014
type (
	Allowance           = model.Allowance
	AllowanceRepository = model.AllowanceRepository
	SmoothingFn         = model.SmoothingFn
)

// SW-REQ-014
var (
	NewAllowance        = model.NewAllowance
	NewAllowanceFromMap = model.NewAllowanceFromMap
)
