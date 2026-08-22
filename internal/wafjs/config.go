package wafjs

import "strings"

// DefaultMaxArtifactBytes bounds each artifact file when Config sets no
// explicit limit. It is a skeleton default, not an approved production
// limit.
const DefaultMaxArtifactBytes int64 = 64 << 20

// CRSPin is the configured CRS provenance pin. The ruleset artifact must
// carry exactly these values; the pin for the current baseline is recorded
// in docs/dev/program/waf-js/crs-pin-provenance.md.
type CRSPin struct {
	// Release is the CRS release tag, for example "v4.25.1".
	Release string
	// ManifestSHA256 is the hex SHA-256 of the pinned CRS source archive.
	ManifestSHA256 string
}

// Config configures one Build. Artifact paths are relative to Root and are
// confined to it.
type Config struct {
	// Root is the artifact root directory all paths resolve within.
	Root string
	// EnginePath is the engine artifact path relative to Root.
	EnginePath string
	// RulesetPath is the generated ruleset artifact path relative to Root.
	RulesetPath string
	// CRSPin is the required provenance pin.
	CRSPin CRSPin
	// EngineSHA256 optionally pins the engine artifact bytes by digest.
	EngineSHA256 string
	// RulesetSHA256 optionally pins the ruleset artifact bytes by digest.
	RulesetSHA256 string
	// MaxEngineBytes bounds the engine artifact size; zero selects
	// DefaultMaxArtifactBytes.
	MaxEngineBytes int64
	// MaxRulesetBytes bounds the ruleset artifact size; zero selects
	// DefaultMaxArtifactBytes.
	MaxRulesetBytes int64
}

// maxEngineLimit returns the effective engine size limit.
func (c Config) maxEngineLimit() int64 {
	if c.MaxEngineBytes == 0 {
		return DefaultMaxArtifactBytes
	}
	return c.MaxEngineBytes
}

// maxRulesetLimit returns the effective ruleset size limit.
func (c Config) maxRulesetLimit() int64 {
	if c.MaxRulesetBytes == 0 {
		return DefaultMaxArtifactBytes
	}
	return c.MaxRulesetBytes
}

// validate rejects structurally invalid configuration. Path resolution,
// digest, and content failures belong to Build, not to configuration.
func (c Config) validate() *Failure {
	if strings.TrimSpace(c.Root) == "" {
		return newFailure(FailureKindConfiguration, "", "root_missing", nil)
	}
	if c.EnginePath == "" {
		return newFailure(FailureKindConfiguration, "", "engine_path_missing", nil)
	}
	if c.RulesetPath == "" {
		return newFailure(FailureKindConfiguration, "", "ruleset_path_missing", nil)
	}
	if c.CRSPin.Release == "" {
		return newFailure(FailureKindConfiguration, "", "pin_release_missing", nil)
	}
	if !isSHA256Hex(c.CRSPin.ManifestSHA256) {
		return newFailure(FailureKindConfiguration, "", "pin_manifest_sha256_invalid", nil)
	}
	if c.EngineSHA256 != "" && !isSHA256Hex(c.EngineSHA256) {
		return newFailure(FailureKindConfiguration, "", "engine_digest_invalid", nil)
	}
	if c.RulesetSHA256 != "" && !isSHA256Hex(c.RulesetSHA256) {
		return newFailure(FailureKindConfiguration, "", "ruleset_digest_invalid", nil)
	}
	if c.MaxEngineBytes < 0 {
		return newFailure(FailureKindConfiguration, "", "max_engine_bytes_negative", nil)
	}
	if c.MaxRulesetBytes < 0 {
		return newFailure(FailureKindConfiguration, "", "max_ruleset_bytes_negative", nil)
	}
	return nil
}

// isSHA256Hex reports whether s is a 64-character hex SHA-256 digest.
func isSHA256Hex(s string) bool {
	if len(s) != sha256HexLen {
		return false
	}
	for i := range s {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// sha256HexLen is the character length of a hex-encoded SHA-256 digest.
const sha256HexLen = 64
