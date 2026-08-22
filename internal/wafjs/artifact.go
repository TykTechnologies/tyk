package wafjs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Artifact format constants. The host defines this contract; the generator
// bead must emit artifacts matching it exactly.
const (
	// artifactSchemaVersion is the only supported artifact schema version.
	artifactSchemaVersion = 1
	// engineArtifactKind identifies the engine artifact.
	engineArtifactKind = "wafjs-engine"
	// rulesetArtifactKind identifies the generated ruleset artifact.
	rulesetArtifactKind = "wafjs-ruleset"
	// engineArtifactVersion is the only supported engine artifact version.
	engineArtifactVersion = "1"
	// rulesetArtifactVersion is the only supported ruleset artifact
	// version.
	rulesetArtifactVersion = "1"
)

// engineArtifact is the engine JavaScript artifact. The javascript field
// carries the engine source; schema, kind, and version pin the contract.
type engineArtifact struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Version       string `json:"version"`
	Javascript    string `json:"javascript"`
}

// rulesetArtifact is the generated ruleset artifact. The rules field is
// opaque to the host: CRS semantics stay in engine JavaScript and
// build-time tooling, never in Go request handling.
type rulesetArtifact struct {
	SchemaVersion     int             `json:"schema_version"`
	Kind              string          `json:"kind"`
	Version           string          `json:"version"`
	CRSRelease        string          `json:"crs_release"`
	CRSManifestSHA256 string          `json:"crs_manifest_sha256"`
	Rules             json.RawMessage `json:"rules"`
}

// resolveArtifactPath confines rel to root: it must be a relative path
// that, after cleaning and symlink resolution, stays inside root and names
// a regular file. It returns the fully resolved path.
func resolveArtifactPath(root, rel string) (string, *Failure) {
	if filepath.IsAbs(rel) {
		return "", newFailure(FailureKindBuild, FailureSourcePath, "path_absolute", nil)
	}
	cleaned := filepath.Clean(rel)
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", newFailure(FailureKindBuild, FailureSourcePath, "path_escape", nil)
	}

	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", newFailure(FailureKindBuild, FailureSourcePath, "root_unavailable", err)
	}
	resolved := filepath.Join(realRoot, cleaned)
	real, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		return "", newFailure(FailureKindBuild, FailureSourcePath, "artifact_missing", err)
	}
	if real != realRoot && !strings.HasPrefix(real, realRoot+string(filepath.Separator)) {
		return "", newFailure(FailureKindBuild, FailureSourcePath, "path_escape", nil)
	}
	return real, nil
}

// loadArtifactFile reads one artifact within its size limit and verifies its
// digest when pinned. name labels the artifact in failure reasons.
func loadArtifactFile(name, root, rel string, maxBytes int64, wantSHA256 string) ([]byte, *Failure) {
	path, f := resolveArtifactPath(root, rel)
	if f != nil {
		return nil, f
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, newFailure(FailureKindBuild, FailureSourcePath, "artifact_missing", err)
	}
	if !info.Mode().IsRegular() {
		return nil, newFailure(FailureKindBuild, FailureSourcePath, "not_regular_file", nil)
	}
	if info.Size() > maxBytes {
		return nil, newFailure(FailureKindBuild, FailureSourceSize, name+"_oversize",
			fmt.Errorf("%s: %d bytes exceeds limit %d", rel, info.Size(), maxBytes))
	}

	// #nosec G304 -- path was confined to the configured artifact root by
	// resolveArtifactPath before this read.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, newFailure(FailureKindBuild, FailureSourcePath, "artifact_unreadable", err)
	}
	if wantSHA256 != "" {
		sum := sha256.Sum256(raw)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), wantSHA256) {
			return nil, newFailure(FailureKindBuild, FailureSourceDigest, name+"_digest_mismatch",
				errors.New("artifact bytes do not match the configured digest"))
		}
	}
	return raw, nil
}

// decodeStrict decodes exactly one JSON document, rejecting unknown fields
// and trailing data.
func decodeStrict(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after JSON document")
	}
	return nil
}

// loadEngineArtifact loads and validates the engine artifact.
func loadEngineArtifact(cfg Config) (engineArtifact, *Failure) {
	raw, f := loadArtifactFile("engine", cfg.Root, cfg.EnginePath, cfg.maxEngineLimit(), cfg.EngineSHA256)
	if f != nil {
		return engineArtifact{}, f
	}

	var art engineArtifact
	if err := decodeStrict(raw, &art); err != nil {
		return engineArtifact{}, newFailure(FailureKindBuild, FailureSourceSchema, "engine_schema", err)
	}
	if art.SchemaVersion != artifactSchemaVersion {
		return engineArtifact{}, newFailure(FailureKindBuild, FailureSourceSchema, "engine_schema_version",
			fmt.Errorf("got %d, want %d", art.SchemaVersion, artifactSchemaVersion))
	}
	if art.Kind != engineArtifactKind {
		return engineArtifact{}, newFailure(FailureKindBuild, FailureSourceSchema, "engine_kind",
			fmt.Errorf("got %q, want %q", art.Kind, engineArtifactKind))
	}
	if art.Version != engineArtifactVersion {
		return engineArtifact{}, newFailure(FailureKindBuild, FailureSourceVersion, "engine_version",
			fmt.Errorf("got %q, want %q", art.Version, engineArtifactVersion))
	}
	if art.Javascript == "" {
		return engineArtifact{}, newFailure(FailureKindBuild, FailureSourceSchema, "engine_javascript_missing", nil)
	}
	return art, nil
}

// loadRulesetArtifact loads, validates, and pin-checks the ruleset
// artifact. The returned rulesLiteral is the canonical JSON encoding of the
// rules payload, safe to embed as a JavaScript expression.
func loadRulesetArtifact(cfg Config) (rulesetArtifact, string, *Failure) {
	raw, f := loadArtifactFile("ruleset", cfg.Root, cfg.RulesetPath, cfg.maxRulesetLimit(), cfg.RulesetSHA256)
	if f != nil {
		return rulesetArtifact{}, "", f
	}

	var art rulesetArtifact
	if err := decodeStrict(raw, &art); err != nil {
		return rulesetArtifact{}, "", newFailure(FailureKindBuild, FailureSourceSchema, "ruleset_schema", err)
	}
	if art.SchemaVersion != artifactSchemaVersion {
		return rulesetArtifact{}, "", newFailure(FailureKindBuild, FailureSourceSchema, "ruleset_schema_version",
			fmt.Errorf("got %d, want %d", art.SchemaVersion, artifactSchemaVersion))
	}
	if art.Kind != rulesetArtifactKind {
		return rulesetArtifact{}, "", newFailure(FailureKindBuild, FailureSourceSchema, "ruleset_kind",
			fmt.Errorf("got %q, want %q", art.Kind, rulesetArtifactKind))
	}
	if art.Version != rulesetArtifactVersion {
		return rulesetArtifact{}, "", newFailure(FailureKindBuild, FailureSourceVersion, "ruleset_version",
			fmt.Errorf("got %q, want %q", art.Version, rulesetArtifactVersion))
	}
	if art.CRSRelease == "" {
		return rulesetArtifact{}, "", newFailure(FailureKindBuild, FailureSourceSchema, "ruleset_crs_release_missing", nil)
	}
	if art.CRSManifestSHA256 == "" {
		return rulesetArtifact{}, "", newFailure(FailureKindBuild, FailureSourceSchema, "ruleset_crs_manifest_missing", nil)
	}
	if art.CRSRelease != cfg.CRSPin.Release {
		return rulesetArtifact{}, "", newFailure(FailureKindBuild, FailureSourcePin, "ruleset_crs_release_mismatch",
			fmt.Errorf("artifact %q does not match configured pin %q", art.CRSRelease, cfg.CRSPin.Release))
	}
	if !strings.EqualFold(art.CRSManifestSHA256, cfg.CRSPin.ManifestSHA256) {
		return rulesetArtifact{}, "", newFailure(FailureKindBuild, FailureSourcePin, "ruleset_crs_manifest_mismatch",
			errors.New("artifact crs_manifest_sha256 does not match configured pin"))
	}

	literal, err := canonicalJSONLiteral(art.Rules)
	if err != nil {
		return rulesetArtifact{}, "", newFailure(FailureKindBuild, FailureSourceSchema, "ruleset_rules_invalid", err)
	}
	return art, literal, nil
}

// canonicalJSONLiteral re-encodes a JSON payload canonically. Go's encoder
// escapes U+2028 and U+2029, which keeps the result a valid JavaScript
// expression at the pinned engine's ES level.
func canonicalJSONLiteral(raw json.RawMessage) (string, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", err
	}
	if v == nil {
		return "", errors.New("rules payload is null")
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
