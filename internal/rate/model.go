package rate

import (
	"github.com/TykTechnologies/tyk/internal/rate/model"
)

type (
	Allowance           = model.Allowance
	AllowanceRepository = model.AllowanceRepository
	SmoothingFn         = model.SmoothingFn
)

var (
	NewAllowance        = model.NewAllowance
	NewAllowanceFromMap = model.NewAllowanceFromMap
)
