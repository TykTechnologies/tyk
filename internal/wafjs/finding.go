package wafjs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/dop251/goja"
)

// Verdict is the engine decision for one inspection.
type Verdict string

// The documented verdicts.
const (
	// VerdictAllow records a request the engine did not block.
	VerdictAllow Verdict = "allow"
	// VerdictBlock records a request the engine decided to block.
	VerdictBlock Verdict = "block"
)

// Finding is the documented inspection result. Inspect returns exactly
// these fields or a typed failure; engine output carrying anything else is
// rejected as a decoding failure.
type Finding struct {
	// Verdict is the engine decision.
	Verdict Verdict `json:"verdict"`
	// AnomalyScore is the inbound anomaly score, when available.
	AnomalyScore int `json:"anomaly_score"`
	// MatchedRuleIDs lists matched rule IDs, sorted ascending.
	MatchedRuleIDs []string `json:"matched_rule_ids"`
	// InspectionScope lists the inspected request collections.
	InspectionScope []string `json:"inspection_scope"`
	// BodyInspected reports whether the request body was inspected.
	BodyInspected bool `json:"body_inspected"`
	// SkipReason is the recorded reason inspection was narrowed, empty for
	// a full inspection.
	SkipReason string `json:"skip_reason"`
	// UnsupportedFeatures lists CRS features this engine does not claim.
	UnsupportedFeatures []string `json:"unsupported_features"`
}

// findingWire mirrors Finding for strict decoding of engine output.
type findingWire Finding

// findingFieldNames is the closed set of fields an engine finding carries.
var findingFieldNames = []string{
	"verdict", "anomaly_score", "matched_rule_ids", "inspection_scope",
	"body_inspected", "skip_reason", "unsupported_features",
}

// checkFindingFields rejects engine findings whose field set is not exactly
// the documented one: no unknown fields, no missing fields.
func checkFindingFields(fields map[string]json.RawMessage) error {
	for _, name := range findingFieldNames {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("finding field %q is missing", name)
		}
	}
	for name := range fields {
		if !slices.Contains(findingFieldNames, name) {
			return fmt.Errorf("finding field %q is not documented", name)
		}
	}
	return nil
}

// decodeFinding converts the engine's return value into a Finding. Unknown
// fields, missing fields, and invalid values are decoding failures; no
// undocumented engine data crosses this boundary.
func decodeFinding(v goja.Value) (Finding, error) {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return Finding{}, newFailure(FailureKindDecoding, "", "finding_missing", nil)
	}

	raw, err := json.Marshal(v.Export())
	if err != nil {
		return Finding{}, newFailure(FailureKindDecoding, "", "finding_not_serializable", err)
	}
	var fields map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fields); err != nil {
		return Finding{}, newFailure(FailureKindDecoding, "", "finding_schema", err)
	}
	if err := checkFindingFields(fields); err != nil {
		return Finding{}, newFailure(FailureKindDecoding, "", "finding_schema", err)
	}
	var wire findingWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return Finding{}, newFailure(FailureKindDecoding, "", "finding_schema", err)
	}

	switch wire.Verdict {
	case VerdictAllow, VerdictBlock:
	default:
		return Finding{}, newFailure(FailureKindDecoding, "", "finding_verdict_invalid",
			fmt.Errorf("engine returned verdict %q", wire.Verdict))
	}
	if wire.AnomalyScore < 0 {
		return Finding{}, newFailure(FailureKindDecoding, "", "finding_anomaly_score_negative",
			fmt.Errorf("engine returned anomaly score %d", wire.AnomalyScore))
	}

	return Finding{
		Verdict:             wire.Verdict,
		AnomalyScore:        wire.AnomalyScore,
		MatchedRuleIDs:      sortedNonEmpty(wire.MatchedRuleIDs),
		InspectionScope:     nonEmpty(wire.InspectionScope),
		BodyInspected:       wire.BodyInspected,
		SkipReason:          wire.SkipReason,
		UnsupportedFeatures: nonEmpty(wire.UnsupportedFeatures),
	}, nil
}

// sortedNonEmpty normalises an absent list to empty and sorts it ascending.
func sortedNonEmpty(values []string) []string {
	out := nonEmpty(values)
	slices.Sort(out)
	return out
}

// nonEmpty normalises absent engine lists to empty, never nil.
func nonEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
