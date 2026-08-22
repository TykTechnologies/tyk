package wafjs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Committed fixture names under testdata/.
const (
	engineFixtureName  = "engine.json"
	rulesetFixtureName = "ruleset.json"
	stubCRSRelease     = "v4.25.1"
	stubCRSManifestSHA = "0539e66e7627fe71c160a644d8fb7ab6e450d53c9de208be5f95a35c70e1a154"
	wrongSHA           = "0000000000000000000000000000000000000000000000000000000000000000"
)

// stubSnapshot returns a minimal valid request snapshot for Inspect.
func stubSnapshot() RequestSnapshot {
	return RequestSnapshot{
		Method:     "GET",
		Scheme:     "https",
		Host:       "example.test",
		RequestURI: "/search?q=1",
		Path:       "/search",
		Proto:      "HTTP/1.1",
		Headers:    map[string][]string{"Accept": {"application/json"}},
		Query:      url.Values{"q": {"1"}},
		Cookies:    []*http.Cookie{{Name: "session", Value: "s1"}},
	}
}

// stubPin returns the CRS pin recorded in the committed ruleset fixture.
func stubPin() CRSPin {
	return CRSPin{Release: stubCRSRelease, ManifestSHA256: stubCRSManifestSHA}
}

// fileDigest returns the lowercase SHA-256 of a file's bytes.
func fileDigest(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// fixtureConfig returns a fully pinned config over the committed fixtures.
func fixtureConfig(t *testing.T) Config {
	t.Helper()
	root, err := filepath.Abs("testdata")
	require.NoError(t, err)
	return Config{
		Root:          root,
		EnginePath:    engineFixtureName,
		RulesetPath:   rulesetFixtureName,
		CRSPin:        stubPin(),
		EngineSHA256:  fileDigest(t, filepath.Join("testdata", engineFixtureName)),
		RulesetSHA256: fileDigest(t, filepath.Join("testdata", rulesetFixtureName)),
	}
}

// loadFixtureMap decodes a committed fixture into a mutable generic map.
func loadFixtureMap(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

// writeArtifact writes a JSON artifact into dir and returns its path.
func writeArtifact(t *testing.T, dir, name string, v any) string {
	t.Helper()
	raw, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

// tempConfig builds a config over a temp root after writing both artifacts.
// Digests match the written bytes so rejections come from the mutated class.
func tempConfig(t *testing.T, mutateEngine, mutateRuleset func(map[string]any)) Config {
	t.Helper()
	root := t.TempDir()
	engine := loadFixtureMap(t, engineFixtureName)
	if mutateEngine != nil {
		mutateEngine(engine)
	}
	ruleset := loadFixtureMap(t, rulesetFixtureName)
	if mutateRuleset != nil {
		mutateRuleset(ruleset)
	}
	enginePath := writeArtifact(t, root, engineFixtureName, engine)
	rulesetPath := writeArtifact(t, root, rulesetFixtureName, ruleset)
	return Config{
		Root:          root,
		EnginePath:    filepath.Base(enginePath),
		RulesetPath:   filepath.Base(rulesetPath),
		CRSPin:        stubPin(),
		EngineSHA256:  fileDigest(t, enginePath),
		RulesetSHA256: fileDigest(t, rulesetPath),
	}
}

// buildFailure asserts err is a build failure with the given source and
// returns it.
func buildFailure(t *testing.T, err error, source FailureSource) *Failure {
	t.Helper()
	require.Error(t, err)
	var f *Failure
	require.ErrorAs(t, err, &f, "Build must return a typed failure, got %v", err)
	assert.Equal(t, FailureKindBuild, f.Kind)
	assert.Equal(t, source, f.Source, "unexpected source for: %v", err)
	assert.NotEmpty(t, f.Reason, "failure must carry a source reason token")
	return f
}

func TestBuildValidFixtureAndInspectAllow(t *testing.T) {
	h := NewHost()
	require.NoError(t, h.Build(context.Background(), fixtureConfig(t)))

	finding, err := h.Inspect(context.Background(), stubSnapshot())
	require.NoError(t, err)

	assert.Equal(t, VerdictAllow, finding.Verdict)
	assert.Equal(t, 0, finding.AnomalyScore)
	assert.Equal(t, []string{}, finding.MatchedRuleIDs)
	assert.Equal(t, []string{"args", "headers", "cookies"}, finding.InspectionScope)
	assert.False(t, finding.BodyInspected)
	assert.Empty(t, finding.SkipReason)
	assert.Equal(t, []string{}, finding.UnsupportedFeatures)
}

func TestInspectFindingCarriesOnlyDocumentedFields(t *testing.T) {
	// The Finding wire shape is closed: exactly these JSON keys decode.
	raw, err := json.Marshal(Finding{
		Verdict:             VerdictBlock,
		AnomalyScore:        7,
		MatchedRuleIDs:      []string{"942100"},
		InspectionScope:     []string{"args"},
		BodyInspected:       true,
		SkipReason:          "",
		UnsupportedFeatures: []string{"multipart"},
	})
	require.NoError(t, err)
	var keys []string
	m := map[string]json.RawMessage{}
	require.NoError(t, json.Unmarshal(raw, &m))
	for k := range m {
		keys = append(keys, k)
	}
	assert.ElementsMatch(t, []string{
		"verdict", "anomaly_score", "matched_rule_ids", "inspection_scope",
		"body_inspected", "skip_reason", "unsupported_features",
	}, keys)
}

func TestBuildRejectionClasses(t *testing.T) {
	tests := []struct {
		name          string
		config        func(t *testing.T, base Config) Config
		mutateEngine  func(map[string]any)
		mutateRuleset func(map[string]any)
		wantSource    FailureSource
		wantReason    string
	}{
		{
			name:         "engine schema_version unsupported",
			mutateEngine: func(m map[string]any) { m["schema_version"] = 2 },
			wantSource:   FailureSourceSchema,
			wantReason:   "engine_schema_version",
		},
		{
			name:          "ruleset schema_version unsupported",
			mutateRuleset: func(m map[string]any) { m["schema_version"] = 0 },
			wantSource:    FailureSourceSchema,
			wantReason:    "ruleset_schema_version",
		},
		{
			name:         "engine unknown field",
			mutateEngine: func(m map[string]any) { m["extra"] = true },
			wantSource:   FailureSourceSchema,
			wantReason:   "engine_schema",
		},
		{
			name:          "ruleset unknown field",
			mutateRuleset: func(m map[string]any) { m["track_hint"] = "x" },
			wantSource:    FailureSourceSchema,
			wantReason:    "ruleset_schema",
		},
		{
			name:         "engine wrong kind",
			mutateEngine: func(m map[string]any) { m["kind"] = "node-engine" },
			wantSource:   FailureSourceSchema,
			wantReason:   "engine_kind",
		},
		{
			name:         "engine javascript missing",
			mutateEngine: func(m map[string]any) { delete(m, "javascript") },
			wantSource:   FailureSourceSchema,
			wantReason:   "engine_javascript_missing",
		},
		{
			name:          "ruleset crs_manifest_sha256 missing",
			mutateRuleset: func(m map[string]any) { delete(m, "crs_manifest_sha256") },
			wantSource:    FailureSourceSchema,
			wantReason:    "ruleset_crs_manifest_missing",
		},
		{
			name:          "ruleset crs_release missing",
			mutateRuleset: func(m map[string]any) { delete(m, "crs_release") },
			wantSource:    FailureSourceSchema,
			wantReason:    "ruleset_crs_release_missing",
		},
		{
			name:         "engine version unsupported",
			mutateEngine: func(m map[string]any) { m["version"] = "2" },
			wantSource:   FailureSourceVersion,
			wantReason:   "engine_version",
		},
		{
			name:          "ruleset version unsupported",
			mutateRuleset: func(m map[string]any) { m["version"] = "3" },
			wantSource:    FailureSourceVersion,
			wantReason:    "ruleset_version",
		},
		{
			name:          "ruleset crs_release pin mismatch",
			mutateRuleset: func(m map[string]any) { m["crs_release"] = "v4.24.0" },
			wantSource:    FailureSourcePin,
			wantReason:    "ruleset_crs_release_mismatch",
		},
		{
			name:          "ruleset crs_manifest_sha256 pin mismatch",
			mutateRuleset: func(m map[string]any) { m["crs_manifest_sha256"] = wrongSHA },
			wantSource:    FailureSourcePin,
			wantReason:    "ruleset_crs_manifest_mismatch",
		},
		{
			name:       "engine digest mismatch",
			config:     func(_ *testing.T, base Config) Config { base.EngineSHA256 = wrongSHA; return base },
			wantSource: FailureSourceDigest,
			wantReason: "engine_digest_mismatch",
		},
		{
			name:       "ruleset digest mismatch",
			config:     func(_ *testing.T, base Config) Config { base.RulesetSHA256 = wrongSHA; return base },
			wantSource: FailureSourceDigest,
			wantReason: "ruleset_digest_mismatch",
		},
		{
			name:       "engine size over limit",
			config:     func(_ *testing.T, base Config) Config { base.MaxEngineBytes = 8; return base },
			wantSource: FailureSourceSize,
			wantReason: "engine_oversize",
		},
		{
			name:       "ruleset size over limit",
			config:     func(_ *testing.T, base Config) Config { base.MaxRulesetBytes = 8; return base },
			wantSource: FailureSourceSize,
			wantReason: "ruleset_oversize",
		},
		{
			name:       "engine path escapes root",
			config:     func(_ *testing.T, base Config) Config { base.EnginePath = "../evil.json"; return base },
			wantSource: FailureSourcePath,
			wantReason: "path_escape",
		},
		{
			name:       "ruleset path absolute",
			config:     func(_ *testing.T, base Config) Config { base.RulesetPath = "/etc/passwd"; return base },
			wantSource: FailureSourcePath,
			wantReason: "path_absolute",
		},
		{
			name:       "engine path missing artifact",
			config:     func(_ *testing.T, base Config) Config { base.EnginePath = "missing.json"; return base },
			wantSource: FailureSourcePath,
			wantReason: "artifact_missing",
		},
		{
			name:       "engine path not a regular file",
			config:     func(_ *testing.T, base Config) Config { base.EnginePath = "."; return base },
			wantSource: FailureSourcePath,
			wantReason: "not_regular_file",
		},
		{
			name: "engine javascript fails to compile",
			mutateEngine: func(m map[string]any) {
				m["javascript"] = "function(( {"
			},
			wantSource: FailureSourceCompile,
			wantReason: "engine_compile",
		},
		{
			name: "engine evaluation throws",
			mutateEngine: func(m map[string]any) {
				m["javascript"] = "throw new Error('engine init failed');"
			},
			wantSource: FailureSourceCompile,
			wantReason: "engine_evaluation",
		},
		{
			name: "engine missing entry point",
			mutateEngine: func(m map[string]any) {
				m["javascript"] = "1;"
			},
			wantSource: FailureSourceABI,
			wantReason: "entry_point_missing",
		},
		{
			name: "engine entry point not callable",
			mutateEngine: func(m map[string]any) {
				m["javascript"] = "globalThis.wafjsInspect = 42;"
			},
			wantSource: FailureSourceABI,
			wantReason: "entry_point_not_callable",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tempConfig(t, tc.mutateEngine, tc.mutateRuleset)
			if tc.config != nil {
				cfg = tc.config(t, cfg)
			}
			h := NewHost()
			f := buildFailure(t, h.Build(context.Background(), cfg), tc.wantSource)
			assert.Equal(t, tc.wantReason, f.Reason)
		})
	}
}

func TestBuildRejectsMalformedArtifactJSON(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, rulesetFixtureName), []byte("{not json"), 0o600))
	enginePath := writeArtifact(t, root, engineFixtureName, loadFixtureMap(t, engineFixtureName))
	cfg := Config{
		Root:        root,
		EnginePath:  filepath.Base(enginePath),
		RulesetPath: rulesetFixtureName,
		CRSPin:      stubPin(),
	}
	f := buildFailure(t, NewHost().Build(context.Background(), cfg), FailureSourceSchema)
	assert.Equal(t, "ruleset_schema", f.Reason)
}

func TestBuildSymlinkEscapeRejected(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	enginePath := writeArtifact(t, outside, engineFixtureName, loadFixtureMap(t, engineFixtureName))
	rulesetPath := writeArtifact(t, root, rulesetFixtureName, loadFixtureMap(t, rulesetFixtureName))
	require.NoError(t, os.Symlink(enginePath, filepath.Join(root, "engine-link.json")))

	cfg := Config{
		Root:        root,
		EnginePath:  "engine-link.json",
		RulesetPath: filepath.Base(rulesetPath),
		CRSPin:      stubPin(),
	}
	f := buildFailure(t, NewHost().Build(context.Background(), cfg), FailureSourcePath)
	assert.Equal(t, "path_escape", f.Reason)
}

func TestBuildConfigurationFailures(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*Config)
		wantReason string
	}{
		{"root missing", func(c *Config) { c.Root = "" }, "root_missing"},
		{"engine path missing", func(c *Config) { c.EnginePath = "" }, "engine_path_missing"},
		{"ruleset path missing", func(c *Config) { c.RulesetPath = "" }, "ruleset_path_missing"},
		{"pin release missing", func(c *Config) { c.CRSPin.Release = "" }, "pin_release_missing"},
		{"pin manifest malformed", func(c *Config) { c.CRSPin.ManifestSHA256 = "not-hex" }, "pin_manifest_sha256_invalid"},
		{"engine digest malformed", func(c *Config) { c.EngineSHA256 = "zz" }, "engine_digest_invalid"},
		{"ruleset digest malformed", func(c *Config) { c.RulesetSHA256 = "zz" }, "ruleset_digest_invalid"},
		{"negative engine limit", func(c *Config) { c.MaxEngineBytes = -1 }, "max_engine_bytes_negative"},
		{"negative ruleset limit", func(c *Config) { c.MaxRulesetBytes = -1 }, "max_ruleset_bytes_negative"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tempConfig(t, nil, nil)
			tc.mutate(&cfg)
			err := NewHost().Build(context.Background(), cfg)
			require.Error(t, err)
			var f *Failure
			require.ErrorAs(t, err, &f)
			assert.Equal(t, FailureKindConfiguration, f.Kind)
			assert.Equal(t, tc.wantReason, f.Reason)
		})
	}
}

func TestInspectFreshTransactionPerCall(t *testing.T) {
	h := NewHost()
	require.NoError(t, h.Build(context.Background(), fixtureConfig(t)))

	for i := range 3 {
		finding, err := h.Inspect(context.Background(), stubSnapshot())
		require.NoError(t, err, "inspection %d", i)
		assert.Equal(t, VerdictAllow, finding.Verdict, "inspection %d", i)
		assert.Empty(t, finding.SkipReason,
			"inspection %d saw a reused transaction (skip_reason %q)", i, finding.SkipReason)
	}
}

func TestInspectStrictFindingDecoding(t *testing.T) {
	blockedOn := func(js string) string {
		return "(function(){var _f=" + js + ";globalThis.wafjsInspect=function(){return _f;};})();"
	}
	tests := []struct {
		name       string
		javascript string
		wantReason string
	}{
		{
			name:       "unknown finding field",
			javascript: blockedOn(`{verdict:"allow",anomaly_score:0,matched_rule_ids:[],inspection_scope:[],body_inspected:false,skip_reason:"",unsupported_features:[],engine_secret:"x"}`),
			wantReason: "finding_schema",
		},
		{
			name:       "missing finding field",
			javascript: blockedOn(`{verdict:"allow",anomaly_score:0,matched_rule_ids:[],inspection_scope:[],body_inspected:false,skip_reason:""}`),
			wantReason: "finding_schema",
		},
		{
			name:       "invalid verdict",
			javascript: blockedOn(`{verdict:"deny",anomaly_score:0,matched_rule_ids:[],inspection_scope:[],body_inspected:false,skip_reason:"",unsupported_features:[]}`),
			wantReason: "finding_verdict_invalid",
		},
		{
			name:       "negative anomaly score",
			javascript: blockedOn(`{verdict:"allow",anomaly_score:-1,matched_rule_ids:[],inspection_scope:[],body_inspected:false,skip_reason:"",unsupported_features:[]}`),
			wantReason: "finding_anomaly_score_negative",
		},
		{
			name:       "finding not an object",
			javascript: "globalThis.wafjsInspect=function(){return 'allow';};",
			wantReason: "finding_schema",
		},
		{
			name:       "finding undefined",
			javascript: "globalThis.wafjsInspect=function(){return undefined;};",
			wantReason: "finding_missing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tempConfig(t, func(m map[string]any) { m["javascript"] = tc.javascript }, nil)
			h := NewHost()
			require.NoError(t, h.Build(context.Background(), cfg))

			_, err := h.Inspect(context.Background(), stubSnapshot())
			require.Error(t, err)
			var f *Failure
			require.ErrorAs(t, err, &f)
			assert.Equal(t, FailureKindDecoding, f.Kind, tc.name)
			assert.Equal(t, tc.wantReason, f.Reason, tc.name)
		})
	}
}

func TestInspectDecodesFindingValues(t *testing.T) {
	js := `(function(){globalThis.wafjsInspect=function(){return {verdict:"block",anomaly_score:9,matched_rule_ids:["942100","941100"],inspection_scope:["args","body"],body_inspected:true,skip_reason:"",unsupported_features:["multipart"]};};})();`
	cfg := tempConfig(t, func(m map[string]any) { m["javascript"] = js }, nil)
	h := NewHost()
	require.NoError(t, h.Build(context.Background(), cfg))

	finding, err := h.Inspect(context.Background(), stubSnapshot())
	require.NoError(t, err)
	assert.Equal(t, VerdictBlock, finding.Verdict)
	assert.Equal(t, 9, finding.AnomalyScore)
	assert.Equal(t, []string{"941100", "942100"}, finding.MatchedRuleIDs, "rule IDs must be sorted ascending")
	assert.Equal(t, []string{"args", "body"}, finding.InspectionScope)
	assert.True(t, finding.BodyInspected)
	assert.Equal(t, []string{"multipart"}, finding.UnsupportedFeatures)
}

func TestInspectJavaScriptFailure(t *testing.T) {
	cfg := tempConfig(t, func(m map[string]any) {
		m["javascript"] = "globalThis.wafjsInspect=function(){throw new Error('boom');};"
	}, nil)
	h := NewHost()
	require.NoError(t, h.Build(context.Background(), cfg))

	_, err := h.Inspect(context.Background(), stubSnapshot())
	require.Error(t, err)
	var f *Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, FailureKindJavaScript, f.Kind)
	assert.Equal(t, "engine_threw", f.Reason)
	assert.Contains(t, err.Error(), "boom")
}

func TestInspectSnapshotFailure(t *testing.T) {
	h := NewHost()
	require.NoError(t, h.Build(context.Background(), fixtureConfig(t)))

	snap := stubSnapshot()
	snap.Method = ""
	_, err := h.Inspect(context.Background(), snap)
	require.Error(t, err)
	var f *Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, FailureKindSnapshot, f.Kind)
	assert.Equal(t, "method_missing", f.Reason)

	snap = stubSnapshot()
	snap.Path = ""
	_, err = h.Inspect(context.Background(), snap)
	require.Error(t, err)
	require.ErrorAs(t, err, &f)
	assert.Equal(t, FailureKindSnapshot, f.Kind)
	assert.Equal(t, "path_missing", f.Reason)
}

func TestInspectDeadlineFailure(t *testing.T) {
	h := NewHost()
	require.NoError(t, h.Build(context.Background(), fixtureConfig(t)))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := h.Inspect(ctx, stubSnapshot())
	require.Error(t, err)
	var f *Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, FailureKindDeadline, f.Kind)
}

func TestCloseReleasesAndDeactivates(t *testing.T) {
	h := NewHost()
	require.NoError(t, h.Build(context.Background(), fixtureConfig(t)))

	_, err := h.Inspect(context.Background(), stubSnapshot())
	require.NoError(t, err)

	require.NoError(t, h.Close())
	require.NoError(t, h.Close(), "Close must be idempotent")

	_, err = h.Inspect(context.Background(), stubSnapshot())
	require.Error(t, err)
	var f *Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, FailureKindPool, f.Kind)
	assert.Equal(t, "engine_not_active", f.Reason)
}

func TestInspectWithoutBuildFailsTyped(t *testing.T) {
	_, err := NewHost().Inspect(context.Background(), stubSnapshot())
	require.Error(t, err)
	var f *Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, FailureKindPool, f.Kind)
}

func TestFailedBuildRetainsPreviousState(t *testing.T) {
	h := NewHost()
	require.NoError(t, h.Build(context.Background(), fixtureConfig(t)))

	before, err := h.Inspect(context.Background(), stubSnapshot())
	require.NoError(t, err)
	require.Equal(t, VerdictAllow, before.Verdict)

	badCfg := fixtureConfig(t)
	badCfg.RulesetPath = "missing.json"
	require.Error(t, h.Build(context.Background(), badCfg))

	after, err := h.Inspect(context.Background(), stubSnapshot())
	require.NoError(t, err, "a failed build must leave the previous engine active")
	assert.Equal(t, before, after)
}

func TestFailedValidationBuildRetainsPreviousState(t *testing.T) {
	h := NewHost()
	require.NoError(t, h.Build(context.Background(), fixtureConfig(t)))

	badCfg := fixtureConfig(t)
	badCfg.RulesetSHA256 = wrongSHA
	require.Error(t, h.Build(context.Background(), badCfg))

	finding, err := h.Inspect(context.Background(), stubSnapshot())
	require.NoError(t, err)
	assert.Equal(t, VerdictAllow, finding.Verdict)
}

func TestBuildContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := NewHost().Build(ctx, fixtureConfig(t))
	require.Error(t, err)
	var f *Failure
	require.ErrorAs(t, err, &f)
	assert.Equal(t, FailureKindDeadline, f.Kind)
}

func TestRebuildSwapsState(t *testing.T) {
	h := NewHost()
	require.NoError(t, h.Build(context.Background(), fixtureConfig(t)))

	blockJS := `(function(){globalThis.wafjsInspect=function(){return {verdict:"block",anomaly_score:5,matched_rule_ids:["920100"],inspection_scope:["args"],body_inspected:false,skip_reason:"",unsupported_features:[]};};})();`
	cfg := tempConfig(t, func(m map[string]any) { m["javascript"] = blockJS }, nil)
	require.NoError(t, h.Build(context.Background(), cfg))

	finding, err := h.Inspect(context.Background(), stubSnapshot())
	require.NoError(t, err)
	assert.Equal(t, VerdictBlock, finding.Verdict)
	assert.Equal(t, []string{"920100"}, finding.MatchedRuleIDs)
}
