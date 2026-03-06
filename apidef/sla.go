package apidef

// SLATarget defines a single SLA/SLO target with an enabled flag,
// the target value, and a warning threshold.
type SLATarget struct {
	Enabled          bool    `bson:"enabled" json:"enabled"`
	TargetValue      float64 `bson:"target_value" json:"target_value"`
	WarningThreshold float64 `bson:"warning_threshold" json:"warning_threshold"`
	SLOPercentage    float64 `bson:"slo_percentage,omitempty" json:"slo_percentage,omitempty"`
}

// SLAConfig holds the SLA/SLO configuration for an API,
// including targets for availability rate, error rate, and latency.
type SLAConfig struct {
	Enabled          bool       `bson:"enabled" json:"enabled"`
	Rate             *SLATarget `bson:"rate,omitempty" json:"rate,omitempty"`
	ErrorRate        *SLATarget `bson:"error_rate,omitempty" json:"error_rate,omitempty"`
	Latency          *SLATarget `bson:"latency,omitempty" json:"latency,omitempty"`
	ComplianceWindow int        `bson:"compliance_window,omitempty" json:"compliance_window,omitempty"`
}
