package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

// Canonical corpus location and shape per docs/dev/program/WAF-AB.corpus.md.
// The fixture is resolved at runtime and never embedded, copied, or relocated.

const (
	wafCorpusSchemaVersion = 1
	wafCorpusFixtureName   = "example-corpus.json"
	wafCorpusModeBlock     = "block"
	wafCorpusModeAudit     = "audit"
	// wafRequestBodyLimit is the shared 10 MiB experiment limit from
	// WAF-AB.contract.md; the oversize fixture case exceeds it by 40 bytes.
	wafRequestBodyLimit = 10 << 20
)

var wafCorpusRelativeDir = filepath.Join("docs", "dev", "program", "waf-corpus")

// wafCorpusReplacementChar is the UTF-8 replacement character U+FFFD. Corpus
// bodies must never be normalised through a string conversion that inserts it.
var wafCorpusReplacementChar = []byte{0xEF, 0xBF, 0xBD}

// wafCorpusFeatureRegistry is the track-neutral required_features vocabulary
// (corpus document Section 5), including libinjection_operators from the
// approved calibration. Unknown names need a format amendment and fail loudly.
var wafCorpusFeatureRegistry = map[string]struct{}{
	"request_body_inspection":    {},
	"body_restoration":           {},
	"request_body_limit":         {},
	"request_body_decompression": {},
	"h2c_upgrade":                {},
	"http2_tls":                  {},
	"rule_exclusions":            {},
	"inspection_failure_policy":  {},
	"libinjection_operators":     {},
}

var wafCorpusAttackFamilies = map[string]struct{}{
	"920": {}, "930": {}, "931": {}, "932": {}, "933": {}, "934": {},
	"941": {}, "942": {}, "943": {}, "944": {}, "none": {},
}

var wafCorpusProvenanceKinds = map[string]struct{}{
	"crs_regression_seed": {},
	"authored":            {},
}

var wafCorpusVerdicts = map[string]struct{}{
	"block": {},
	"allow": {},
}

type wafCorpusProvenance struct {
	Kind             string `json:"kind"`
	SourceRelease    string `json:"source_release"`
	SourceTag        string `json:"source_tag"`
	SourceFile       string `json:"source_file"`
	OriginalTestName string `json:"original_test_name"`
	License          string `json:"license"`
	AdaptationNotes  string `json:"adaptation_notes"`
}

type wafCorpusCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type wafCorpusRequest struct {
	Host         string              `json:"host"`
	Method       string              `json:"method"`
	Path         string              `json:"path"`
	Proto        string              `json:"proto"`
	Headers      map[string]string   `json:"headers"`
	HeadersArray map[string][]string `json:"headers_array"`
	QueryParams  map[string]string   `json:"query_params"`
	Cookies      []wafCorpusCookie   `json:"cookies"`
	BodyBase64   string              `json:"body_base64"`
	BodyRepeat   *int                `json:"body_repeat"`
}

type wafCorpusAnomalyScore struct {
	Min *int `json:"min"`
	Max *int `json:"max"`
}

type wafCorpusMatchedRuleIDs struct {
	Required  []string `json:"required"`
	Forbidden []string `json:"forbidden"`
}

type wafCorpusExpectation struct {
	Verdict         string                   `json:"verdict"`
	Enforced        bool                     `json:"enforced"`
	Status          int                      `json:"status"`
	UpstreamReached bool                     `json:"upstream_reached"`
	AnomalyScore    *wafCorpusAnomalyScore   `json:"anomaly_score"`
	MatchedRuleIDs  *wafCorpusMatchedRuleIDs `json:"matched_rule_ids"`
	LogRecord       bool                     `json:"log_record"`
	BodyMatch       string                   `json:"body_match"`
}

type wafCorpusFailurePolicy struct {
	FailOpen   wafCorpusExpectation `json:"fail_open"`
	FailClosed wafCorpusExpectation `json:"fail_closed"`
}

type wafCorpusCase struct {
	SchemaVersion    int                             `json:"schema_version"`
	ID               string                          `json:"id"`
	AttackFamily     string                          `json:"attack_family"`
	Applicable       bool                            `json:"applicable"`
	Provenance       wafCorpusProvenance             `json:"provenance"`
	RequiredFeatures []string                        `json:"required_features"`
	Request          wafCorpusRequest                `json:"request"`
	Expectations     map[string]wafCorpusExpectation `json:"expectations"`
	FailurePolicy    *wafCorpusFailurePolicy         `json:"failure_policy"`
}

// wafCorpusDirFrom walks up from start until it finds the canonical corpus
// directory docs/dev/program/waf-corpus (corpus document Section 1).
func wafCorpusDirFrom(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("waf corpus: resolve start %q: %w", start, err)
	}
	for {
		candidate := filepath.Join(dir, wafCorpusRelativeDir)
		if info, statErr := os.Stat(candidate); statErr == nil && info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("waf corpus: canonical directory %s not found in or above %s", wafCorpusRelativeDir, start)
		}
		dir = parent
	}
}

// wafCorpusDir resolves the canonical corpus directory from the test working
// directory.
func wafCorpusDir(t *testing.T) string {
	t.Helper()
	dir, err := wafCorpusDirFrom(".")
	require.NoError(t, err)
	return dir
}

// loadWAFCorpusFixture reads and strictly decodes the canonical fixture.
func loadWAFCorpusFixture(dir string) ([]wafCorpusCase, error) {
	raw, err := os.ReadFile(filepath.Join(dir, wafCorpusFixtureName))
	if err != nil {
		return nil, fmt.Errorf("waf corpus: read fixture: %w", err)
	}
	return decodeWAFCorpus(raw)
}

// decodeWAFCorpus strictly decodes a fixture JSON array into pure data.
func decodeWAFCorpus(raw []byte) ([]wafCorpusCase, error) {
	var elements []json.RawMessage
	if err := json.Unmarshal(raw, &elements); err != nil {
		return nil, fmt.Errorf("waf corpus: fixture must be a JSON array of cases: %w", err)
	}
	cases := make([]wafCorpusCase, 0, len(elements))
	seen := make(map[string]struct{}, len(elements))
	for i, element := range elements {
		c, err := decodeWAFCorpusCase(element)
		if err != nil {
			return nil, fmt.Errorf("waf corpus: element %d: %w", i, err)
		}
		if _, dup := seen[c.ID]; dup {
			return nil, fmt.Errorf("waf corpus: element %d: duplicate case id %q", i, c.ID)
		}
		seen[c.ID] = struct{}{}
		cases = append(cases, c)
	}
	return cases, nil
}

// decodeWAFCorpusCase decodes one case with strict unknown-field rejection.
// Every failure names the case id.
func decodeWAFCorpusCase(element json.RawMessage) (wafCorpusCase, error) {
	var c wafCorpusCase
	dec := json.NewDecoder(bytes.NewReader(element))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("case %q: schema: %w", wafCorpusCaseID(element), err)
	}
	if err := c.validate(); err != nil {
		return c, err
	}
	return c, nil
}

// wafCorpusCaseID recovers the id from a raw element so rejection errors can
// name the case even when strict decoding fails.
func wafCorpusCaseID(element json.RawMessage) string {
	var idOnly struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(element, &idOnly); err != nil {
		return ""
	}
	return idOnly.ID
}

func (c wafCorpusCase) validate() error {
	if !strings.HasPrefix(c.ID, "corpus-") {
		return fmt.Errorf("case %q: id must be a non-empty corpus-* identifier", c.ID)
	}
	if c.SchemaVersion != wafCorpusSchemaVersion {
		return fmt.Errorf("case %q: unsupported schema_version %d (want %d)", c.ID, c.SchemaVersion, wafCorpusSchemaVersion)
	}
	if _, ok := wafCorpusAttackFamilies[c.AttackFamily]; !ok {
		return fmt.Errorf("case %q: unknown attack_family %q", c.ID, c.AttackFamily)
	}
	if _, ok := wafCorpusProvenanceKinds[c.Provenance.Kind]; !ok {
		return fmt.Errorf("case %q: unknown provenance.kind %q", c.ID, c.Provenance.Kind)
	}
	for _, feature := range c.RequiredFeatures {
		if _, ok := wafCorpusFeatureRegistry[feature]; !ok {
			return fmt.Errorf("case %q: unknown required_features entry %q (format amendment required)", c.ID, feature)
		}
	}
	for mode := range c.Expectations {
		if mode != wafCorpusModeBlock && mode != wafCorpusModeAudit {
			return fmt.Errorf("case %q: unknown expectations mode %q", c.ID, mode)
		}
	}
	for _, mode := range []string{wafCorpusModeBlock, wafCorpusModeAudit} {
		expectation, ok := c.Expectations[mode]
		if !ok {
			return fmt.Errorf("case %q: expectations must define mode %q", c.ID, mode)
		}
		if err := expectation.validate(c.ID, "expectations."+mode); err != nil {
			return err
		}
	}
	if c.Request.Path == "" {
		return fmt.Errorf("case %q: request.path must not be empty", c.ID)
	}
	if c.Request.BodyRepeat != nil && *c.Request.BodyRepeat < 1 {
		return fmt.Errorf("case %q: body_repeat must be at least 1, got %d", c.ID, *c.Request.BodyRepeat)
	}
	if _, err := base64.StdEncoding.DecodeString(c.Request.BodyBase64); err != nil {
		return fmt.Errorf("case %q: body_base64: %w", c.ID, err)
	}
	if c.FailurePolicy != nil {
		if err := c.FailurePolicy.FailOpen.validate(c.ID, "failure_policy.fail_open"); err != nil {
			return err
		}
		if err := c.FailurePolicy.FailClosed.validate(c.ID, "failure_policy.fail_closed"); err != nil {
			return err
		}
	}
	return nil
}

func (e wafCorpusExpectation) validate(caseID, where string) error {
	if _, ok := wafCorpusVerdicts[e.Verdict]; !ok {
		return fmt.Errorf("case %q: %s: unknown verdict %q", caseID, where, e.Verdict)
	}
	if e.AnomalyScore != nil && e.AnomalyScore.Min == nil && e.AnomalyScore.Max == nil {
		return fmt.Errorf("case %q: %s: anomaly_score requires min or max", caseID, where)
	}
	return nil
}

// bodyRepeat returns the repeat factor applied to the decoded body (default 1).
func (r wafCorpusRequest) bodyRepeat() int {
	if r.BodyRepeat != nil && *r.BodyRepeat > 0 {
		return *r.BodyRepeat
	}
	return 1
}

// bodySeed decodes body_base64 into the exact seed bytes. Empty means no body.
func (c wafCorpusCase) bodySeed() ([]byte, error) {
	if c.Request.BodyBase64 == "" {
		return nil, nil
	}
	seed, err := base64.StdEncoding.DecodeString(c.Request.BodyBase64)
	if err != nil {
		return nil, fmt.Errorf("case %q: body_base64: %w", c.ID, err)
	}
	return seed, nil
}

// bodyBytes returns the exact request body: the decoded body_base64 seed
// repeated body_repeat times (default 1). No normalisation is applied, so
// malformed encodings and binary payloads survive byte-for-byte.
func (c wafCorpusCase) bodyBytes() ([]byte, error) {
	seed, err := c.bodySeed()
	if err != nil {
		return nil, err
	}
	if len(seed) == 0 {
		return nil, nil
	}
	return bytes.Repeat(seed, c.Request.bodyRepeat()), nil
}

// testCase maps the corpus request onto test.TestCase per the corpus document
// Section 4 field table; Data receives the exact expanded body bytes and the
// method defaults to GET.
func (c wafCorpusCase) testCase() (test.TestCase, error) {
	body, err := c.bodyBytes()
	if err != nil {
		return test.TestCase{}, err
	}
	req := c.Request
	tc := test.TestCase{
		Host:         req.Host,
		Method:       req.Method,
		Path:         req.Path,
		Proto:        req.Proto,
		Headers:      req.Headers,
		HeadersArray: req.HeadersArray,
		QueryParams:  req.QueryParams,
	}
	if tc.Method == "" {
		tc.Method = "GET"
	}
	for _, cookie := range req.Cookies {
		tc.Cookies = append(tc.Cookies, &http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	if body != nil {
		tc.Data = body
	}
	return tc, nil
}

func wafCorpusSHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Test helpers over synthetic minimal cases.

const minimWAFCorpusCaseID = "corpus-loader-minimal"

func minimWAFCorpusCase() map[string]any {
	return map[string]any{
		"schema_version":    wafCorpusSchemaVersion,
		"id":                minimWAFCorpusCaseID,
		"attack_family":     "none",
		"applicable":        true,
		"provenance":        map[string]any{"kind": "authored"},
		"required_features": []any{},
		"request": map[string]any{
			"method":        "GET",
			"path":          "/",
			"proto":         "HTTP/1.1",
			"headers":       map[string]any{},
			"headers_array": map[string]any{},
			"query_params":  map[string]any{},
			"cookies":       []any{},
			"body_base64":   "",
		},
		"expectations": map[string]any{
			"block": map[string]any{"verdict": "allow", "enforced": false, "status": 200, "upstream_reached": true},
			"audit": map[string]any{"verdict": "allow", "enforced": false, "status": 200, "upstream_reached": true, "log_record": false},
		},
	}
}

func jsonObjectOf(value any) map[string]any {
	object, ok := value.(map[string]any)
	if !ok {
		panic("value is not a JSON object")
	}
	return object
}

func decodeMinimWAFCorpusCase(t *testing.T, mutate ...func(m map[string]any)) wafCorpusCase {
	t.Helper()
	m := minimWAFCorpusCase()
	for _, mutateCase := range mutate {
		mutateCase(m)
	}
	raw, err := json.Marshal([]any{m})
	require.NoError(t, err)
	cases, err := decodeWAFCorpus(raw)
	require.NoError(t, err)
	require.Len(t, cases, 1)
	return cases[0]
}

func rejectMinimWAFCorpusCase(t *testing.T, mutate func(m map[string]any)) error {
	t.Helper()
	m := minimWAFCorpusCase()
	mutate(m)
	raw, err := json.Marshal([]any{m})
	require.NoError(t, err)
	_, decodeErr := decodeWAFCorpus(raw)
	require.Error(t, decodeErr)
	return decodeErr
}

// Fixture expectations.

type wafCorpusCaseSummary struct {
	family   string
	method   string
	features []string
}

// wafCorpusFixtureSummary records the decoded shape of every case in the
// canonical fixture.
var wafCorpusFixtureSummary = map[string]wafCorpusCaseSummary{
	"corpus-920-host-ip":                     {family: "920", method: "GET", features: []string{}},
	"corpus-930-lfi-passwd":                  {family: "930", method: "GET", features: []string{}},
	"corpus-931-rfi-url":                     {family: "931", method: "GET", features: []string{}},
	"corpus-932-rce-system":                  {family: "932", method: "POST", features: []string{"request_body_inspection"}},
	"corpus-933-php-wrapper":                 {family: "933", method: "GET", features: []string{}},
	"corpus-934-nodejs-require":              {family: "934", method: "GET", features: []string{}},
	"corpus-941-xss-libinjection":            {family: "941", method: "GET", features: []string{"libinjection_operators"}},
	"corpus-942-sqli-libinjection":           {family: "942", method: "GET", features: []string{"libinjection_operators"}},
	"corpus-943-session-fixation":            {family: "943", method: "GET", features: []string{}},
	"corpus-944-java-runtime":                {family: "944", method: "POST", features: []string{"request_body_inspection"}},
	"corpus-benign-get":                      {family: "none", method: "GET", features: []string{}},
	"corpus-oversize-body":                   {family: "none", method: "POST", features: []string{"request_body_limit"}},
	"corpus-h2c-upgrade":                     {family: "none", method: "POST", features: []string{"h2c_upgrade"}},
	"corpus-tls-h2-benign":                   {family: "none", method: "POST", features: []string{"http2_tls"}},
	"corpus-isolation-malformed-then-attack": {family: "942", method: "POST", features: []string{"request_body_decompression"}},
	"corpus-exclusion-arg-name":              {family: "930", method: "GET", features: []string{"rule_exclusions"}},
	"corpus-body-restore-inspected":          {family: "930", method: "POST", features: []string{"request_body_inspection", "body_restoration"}},
	"corpus-fail-inspection":                 {family: "none", method: "POST", features: []string{"inspection_failure_policy"}},
}

type wafCorpusBodyDigest struct {
	size   int
	sha256 string
}

// wafCorpusBodyDigests records the size and sha256 of the fully expanded body
// (body_base64 decoded and repeated body_repeat times) for every fixture case.
// Values were computed independently of this loader with python3 hashlib over
// docs/dev/program/waf-corpus/example-corpus.json, so equality proves byte
// exactness rather than self-consistency.
var wafCorpusBodyDigests = map[string]wafCorpusBodyDigest{
	"corpus-920-host-ip":                     {size: 0, sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	"corpus-930-lfi-passwd":                  {size: 0, sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	"corpus-931-rfi-url":                     {size: 0, sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	"corpus-932-rce-system":                  {size: 18, sha256: "e6dc1aec199d58a76b0947fce22a63a2ba17067d00bc59c29ea37ae11e4a3af0"},
	"corpus-933-php-wrapper":                 {size: 0, sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	"corpus-934-nodejs-require":              {size: 0, sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	"corpus-941-xss-libinjection":            {size: 0, sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	"corpus-942-sqli-libinjection":           {size: 0, sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	"corpus-943-session-fixation":            {size: 0, sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	"corpus-944-java-runtime":                {size: 40, sha256: "b6f0eeea201692084b7629ca03075893a9c5b1302bb9a2780195153eb162463e"},
	"corpus-benign-get":                      {size: 0, sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	"corpus-oversize-body":                   {size: 10485800, sha256: "38b7d497df18237571283ef8262aed6088655d7268f3c7a1b9c54942db7fbf64"},
	"corpus-h2c-upgrade":                     {size: 6, sha256: "86c4e48de5ee35b40191299d1035083a3fc7d9c6d35b8cb10c4b0bcf3c915472"},
	"corpus-tls-h2-benign":                   {size: 6, sha256: "86c4e48de5ee35b40191299d1035083a3fc7d9c6d35b8cb10c4b0bcf3c915472"},
	"corpus-isolation-malformed-then-attack": {size: 24, sha256: "e01579a1014ae2c19a2ca6f5341eedf282300a65bb54de781cddc2ff6b5364ed"},
	"corpus-exclusion-arg-name":              {size: 0, sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	"corpus-body-restore-inspected":          {size: 24, sha256: "2a3be1bef34e60366aabcb8792ded168468ee8841df4c2b1bc53e0edb323d19f"},
	"corpus-fail-inspection":                 {size: 10, sha256: "59a13aa892e3bdd2587c59e6337b5179ac1296970d10728c33fba365826a1864"},
}

func TestWAFSharedCorpusLoader(t *testing.T) {
	t.Run("resolves the canonical directory from nested working directories", func(t *testing.T) {
		starts := []string{
			".",                              // the gateway test working directory
			"..",                             // the repository root
			"../apidef/oas",                  // a package two levels deep
			"../internal/wafjs",              // another package two levels deep
			"../docs",                        // three levels above the corpus
			"../docs/dev/program",            // the parent of the corpus directory
			"../docs/dev/program/waf-corpus", // the corpus directory itself
		}
		var want string
		for _, start := range starts {
			dir, err := wafCorpusDirFrom(start)
			require.NoErrorf(t, err, "start %q", start)
			abs, err := filepath.Abs(dir)
			require.NoError(t, err)
			if want == "" {
				want = abs
			}
			assert.Equalf(t, want, abs, "start %q resolved a different corpus directory", start)
			assert.FileExistsf(t, filepath.Join(dir, wafCorpusFixtureName), "start %q", start)
		}
	})

	t.Run("fails clearly outside the repository", func(t *testing.T) {
		_, err := wafCorpusDirFrom(t.TempDir())
		require.Error(t, err)
		assert.Contains(t, err.Error(), wafCorpusRelativeDir)
	})

	t.Run("decodes the real fixture completely", func(t *testing.T) {
		cases, err := loadWAFCorpusFixture(wafCorpusDir(t))
		require.NoError(t, err)
		require.Len(t, cases, len(wafCorpusFixtureSummary))

		byID := make(map[string]wafCorpusCase, len(cases))
		for _, c := range cases {
			byID[c.ID] = c
			assert.Equalf(t, wafCorpusSchemaVersion, c.SchemaVersion, "case %s schema_version", c.ID)
		}

		for id, want := range wafCorpusFixtureSummary {
			c, ok := byID[id]
			require.Truef(t, ok, "fixture case %s missing", id)
			assert.Equalf(t, want.family, c.AttackFamily, "case %s attack_family", id)
			assert.Equalf(t, want.method, c.Request.Method, "case %s method", id)
			assert.Equalf(t, want.features, c.RequiredFeatures, "case %s required_features", id)
			assert.Truef(t, c.Applicable, "fixture case %s applicable", id)
		}

		assert.Equal(t, "10.0.0.1", byID["corpus-920-host-ip"].Request.Host)
		assert.Equal(t, []string{"text/html", "application/xhtml+xml"}, byID["corpus-941-xss-libinjection"].Request.HeadersArray["Accept"])
		assert.Contains(t, byID["corpus-942-sqli-libinjection"].RequiredFeatures, "libinjection_operators")

		cookieCase := byID["corpus-943-session-fixation"]
		require.Len(t, cookieCase.Request.Cookies, 1)
		assert.Equal(t, "JSESSIONID", cookieCase.Request.Cookies[0].Name)
		assert.Equal(t, "FIXED1234567890", cookieCase.Request.Cookies[0].Value)

		oversize := byID["corpus-oversize-body"]
		require.NotNil(t, oversize.Request.BodyRepeat, "oversize case must declare body_repeat")
		assert.Equal(t, 104858, *oversize.Request.BodyRepeat)

		exclusion := byID["corpus-exclusion-arg-name"]
		require.NotNil(t, exclusion.Expectations[wafCorpusModeBlock].MatchedRuleIDs)
		assert.Equal(t, []string{"930120"}, exclusion.Expectations[wafCorpusModeBlock].MatchedRuleIDs.Forbidden)

		restore := byID["corpus-body-restore-inspected"]
		assert.True(t, restore.Expectations[wafCorpusModeBlock].Enforced)
		assert.Equal(t, 403, restore.Expectations[wafCorpusModeBlock].Status)
		assert.True(t, restore.Expectations[wafCorpusModeAudit].LogRecord)
		assert.Equal(t, "etc/passwd", restore.Expectations[wafCorpusModeAudit].BodyMatch)

		failure := byID["corpus-fail-inspection"]
		require.NotNil(t, failure.FailurePolicy, "failure-policy case must decode its legs")
		assert.Equal(t, "allow", failure.FailurePolicy.FailOpen.Verdict)
		assert.Equal(t, 200, failure.FailurePolicy.FailOpen.Status)
		assert.False(t, failure.FailurePolicy.FailOpen.Enforced)
		assert.True(t, failure.FailurePolicy.FailOpen.UpstreamReached)
		assert.Equal(t, "block", failure.FailurePolicy.FailClosed.Verdict)
		assert.Equal(t, 503, failure.FailurePolicy.FailClosed.Status)
		assert.True(t, failure.FailurePolicy.FailClosed.Enforced)
		assert.False(t, failure.FailurePolicy.FailClosed.UpstreamReached)

		assert.Equal(t, "HTTP/2.0", byID["corpus-tls-h2-benign"].Request.Proto)
		assert.Equal(t, "crs_regression_seed", byID["corpus-920-host-ip"].Provenance.Kind)
		assert.Equal(t, "authored", failure.Provenance.Kind)
		assert.Equal(t, "Apache-2.0", byID["corpus-932-rce-system"].Provenance.License)
	})

	t.Run("maps corpus requests onto test.TestCase", func(t *testing.T) {
		cases, err := loadWAFCorpusFixture(wafCorpusDir(t))
		require.NoError(t, err)
		byID := make(map[string]wafCorpusCase, len(cases))
		for _, c := range cases {
			byID[c.ID] = c
		}

		hostCase, err := byID["corpus-920-host-ip"].testCase()
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.1", hostCase.Host)
		assert.Equal(t, "GET", hostCase.Method)
		assert.Equal(t, "/", hostCase.Path)
		assert.Equal(t, "HTTP/1.1", hostCase.Proto)
		assert.Nil(t, hostCase.Data)

		xssCase, err := byID["corpus-941-xss-libinjection"].testCase()
		require.NoError(t, err)
		assert.Equal(t, []string{"text/html", "application/xhtml+xml"}, xssCase.HeadersArray["Accept"])
		assert.Equal(t, map[string]string{"q": "<script>alert(1)</script>"}, xssCase.QueryParams)

		cookieCase, err := byID["corpus-943-session-fixation"].testCase()
		require.NoError(t, err)
		require.Len(t, cookieCase.Cookies, 1)
		assert.Equal(t, "JSESSIONID", cookieCase.Cookies[0].Name)
		assert.Equal(t, "FIXED1234567890", cookieCase.Cookies[0].Value)

		rceCase, err := byID["corpus-932-rce-system"].testCase()
		require.NoError(t, err)
		assert.Equal(t, "application/x-www-form-urlencoded", rceCase.Headers["Content-Type"])
		assert.Equal(t, []byte("code=system('ls');"), rceCase.Data)

		oversizeCase, err := byID["corpus-oversize-body"].testCase()
		require.NoError(t, err)
		data, ok := oversizeCase.Data.([]byte)
		require.True(t, ok, "Data must carry the expanded body as bytes")
		assert.Len(t, data, 10485800)
	})

	t.Run("maps a minimal request with the GET default", func(t *testing.T) {
		c := decodeMinimWAFCorpusCase(t, func(m map[string]any) {
			delete(jsonObjectOf(m["request"]), "method")
		})
		tc, err := c.testCase()
		require.NoError(t, err)
		assert.Equal(t, "GET", tc.Method)
		assert.Nil(t, tc.Data)
	})

	t.Run("rejects invalid cases loudly with the case id", func(t *testing.T) {
		tests := []struct {
			name     string
			mutate   func(m map[string]any)
			contains []string
		}{
			{
				name: "unknown top-level field",
				mutate: func(m map[string]any) {
					m["track_extension"] = true
				},
				contains: []string{minimWAFCorpusCaseID, "track_extension"},
			},
			{
				name: "unknown request field",
				mutate: func(m map[string]any) {
					jsonObjectOf(m["request"])["retry"] = true
				},
				contains: []string{minimWAFCorpusCaseID, "retry"},
			},
			{
				name: "unknown expectation field",
				mutate: func(m map[string]any) {
					block := jsonObjectOf(jsonObjectOf(m["expectations"])[wafCorpusModeBlock])
					block["score_exact"] = 7
				},
				contains: []string{minimWAFCorpusCaseID, "score_exact"},
			},
			{
				name: "unknown provenance field",
				mutate: func(m map[string]any) {
					jsonObjectOf(m["provenance"])["track_hint"] = "x"
				},
				contains: []string{minimWAFCorpusCaseID, "track_hint"},
			},
			{
				name: "unknown cookie field",
				mutate: func(m map[string]any) {
					jsonObjectOf(m["request"])["cookies"] = []any{
						map[string]any{"name": "a", "value": "b", "secure": true},
					}
				},
				contains: []string{minimWAFCorpusCaseID, "secure"},
			},
			{
				name: "unknown failure_policy field",
				mutate: func(m map[string]any) {
					m["failure_policy"] = map[string]any{
						"fail_open": map[string]any{
							"verdict": "allow", "enforced": false, "status": 200,
							"upstream_reached": true, "log_record": true,
						},
						"fail_closed": map[string]any{
							"verdict": "block", "enforced": true, "status": 503,
							"upstream_reached": false, "log_record": true,
						},
						"mid_policy": map[string]any{},
					}
				},
				contains: []string{minimWAFCorpusCaseID, "mid_policy"},
			},
			{
				name: "unknown schema_version",
				mutate: func(m map[string]any) {
					m["schema_version"] = 2
				},
				contains: []string{minimWAFCorpusCaseID, "unsupported schema_version 2"},
			},
			{
				name: "zero schema_version",
				mutate: func(m map[string]any) {
					m["schema_version"] = 0
				},
				contains: []string{minimWAFCorpusCaseID, "unsupported schema_version 0"},
			},
			{
				name: "unknown required_features entry",
				mutate: func(m map[string]any) {
					m["required_features"] = []any{"teleportation"}
				},
				contains: []string{minimWAFCorpusCaseID, "teleportation"},
			},
			{
				name: "unknown expectations mode",
				mutate: func(m map[string]any) {
					jsonObjectOf(m["expectations"])["detect"] = map[string]any{
						"verdict": "allow", "enforced": false, "status": 200, "upstream_reached": true,
					}
				},
				contains: []string{minimWAFCorpusCaseID, "unknown expectations mode", "detect"},
			},
			{
				name: "missing audit mode",
				mutate: func(m map[string]any) {
					delete(jsonObjectOf(m["expectations"]), wafCorpusModeAudit)
				},
				contains: []string{minimWAFCorpusCaseID, "must define mode", wafCorpusModeAudit},
			},
			{
				name: "unknown verdict",
				mutate: func(m map[string]any) {
					block := jsonObjectOf(jsonObjectOf(m["expectations"])[wafCorpusModeBlock])
					block["verdict"] = "deny"
				},
				contains: []string{minimWAFCorpusCaseID, "unknown verdict", "deny"},
			},
			{
				name: "unknown attack_family",
				mutate: func(m map[string]any) {
					m["attack_family"] = "951"
				},
				contains: []string{minimWAFCorpusCaseID, "unknown attack_family", "951"},
			},
			{
				name: "unknown provenance kind",
				mutate: func(m map[string]any) {
					jsonObjectOf(m["provenance"])["kind"] = "guessed"
				},
				contains: []string{minimWAFCorpusCaseID, "unknown provenance.kind", "guessed"},
			},
			{
				name: "invalid body_base64",
				mutate: func(m map[string]any) {
					jsonObjectOf(m["request"])["body_base64"] = "!!not-base64!!"
				},
				contains: []string{minimWAFCorpusCaseID, "body_base64"},
			},
			{
				name: "zero body_repeat",
				mutate: func(m map[string]any) {
					jsonObjectOf(m["request"])["body_repeat"] = 0
				},
				contains: []string{minimWAFCorpusCaseID, "body_repeat must be at least 1"},
			},
			{
				name: "missing id",
				mutate: func(m map[string]any) {
					delete(m, "id")
				},
				contains: []string{"id must be a non-empty corpus-* identifier"},
			},
			{
				name: "id outside the corpus namespace",
				mutate: func(m map[string]any) {
					m["id"] = "track-local-case"
				},
				contains: []string{"id must be a non-empty corpus-* identifier"},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				err := rejectMinimWAFCorpusCase(t, tc.mutate)
				for _, want := range tc.contains {
					assert.Contains(t, err.Error(), want)
				}
			})
		}
	})

	t.Run("rejects duplicate case ids", func(t *testing.T) {
		raw, err := json.Marshal([]any{minimWAFCorpusCase(), minimWAFCorpusCase()})
		require.NoError(t, err)
		_, decodeErr := decodeWAFCorpus(raw)
		require.Error(t, decodeErr)
		assert.Contains(t, decodeErr.Error(), "duplicate case id")
		assert.Contains(t, decodeErr.Error(), minimWAFCorpusCaseID)
	})

	t.Run("rejects a non-array fixture", func(t *testing.T) {
		_, err := decodeWAFCorpus([]byte(`{"schema_version": 1}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be a JSON array")
	})
}

func TestWAFSharedCorpusBodyBytes(t *testing.T) {
	cases, err := loadWAFCorpusFixture(wafCorpusDir(t))
	require.NoError(t, err)

	byID := make(map[string]wafCorpusCase, len(cases))
	for _, c := range cases {
		byID[c.ID] = c
	}

	t.Run("expanded body digests match for every fixture case", func(t *testing.T) {
		require.Len(t, cases, len(wafCorpusBodyDigests))
		for _, c := range cases {
			want, ok := wafCorpusBodyDigests[c.ID]
			require.Truef(t, ok, "no expected digest recorded for %s", c.ID)
			body, err := c.bodyBytes()
			require.NoErrorf(t, err, "case %s", c.ID)
			assert.Lenf(t, body, want.size, "case %s expanded body size", c.ID)
			assert.Equalf(t, want.sha256, wafCorpusSHA256Hex(body), "case %s expanded body digest", c.ID)
			assert.Falsef(t, bytes.Contains(body, wafCorpusReplacementChar), "case %s must not gain U+FFFD", c.ID)
		}
	})

	t.Run("oversize body expands to 10 MiB plus 40 bytes", func(t *testing.T) {
		oversize, ok := byID["corpus-oversize-body"]
		require.True(t, ok)
		body, err := oversize.bodyBytes()
		require.NoError(t, err)
		require.Len(t, body, wafRequestBodyLimit+40)
		assert.Equal(t, 10485800, len(body))
		seed, err := oversize.bodySeed()
		require.NoError(t, err)
		assert.Equal(t, bytes.Repeat([]byte{'A'}, 100), seed)
		assert.Equal(t, byte('A'), body[0])
		assert.Equal(t, byte('A'), body[len(body)-1])
	})

	t.Run("covers the exact 10 MiB limit and the first byte above it", func(t *testing.T) {
		setSingleByteBody := func(repeat int) func(m map[string]any) {
			return func(m map[string]any) {
				request := jsonObjectOf(m["request"])
				request["method"] = "POST"
				request["body_base64"] = base64.StdEncoding.EncodeToString([]byte("A"))
				request["body_repeat"] = repeat
			}
		}

		atLimit := decodeMinimWAFCorpusCase(t, setSingleByteBody(wafRequestBodyLimit))
		atBody, err := atLimit.bodyBytes()
		require.NoError(t, err)
		require.Len(t, atBody, wafRequestBodyLimit)
		assert.Equal(t, "eb6183addde05c2196ce25e6fa34a4baf20f9bf30d33892f452a9a1e88c9a472", wafCorpusSHA256Hex(atBody))

		overLimit := decodeMinimWAFCorpusCase(t, setSingleByteBody(wafRequestBodyLimit+1))
		overBody, err := overLimit.bodyBytes()
		require.NoError(t, err)
		require.Len(t, overBody, wafRequestBodyLimit+1)
		assert.Equal(t, "4b5d4e4afa64835d7a9cc3a10ffeaa4160e49503e451f26173b659116c31a0ea", wafCorpusSHA256Hex(overBody))
	})

	t.Run("body_repeat multiplies the decoded seed exactly", func(t *testing.T) {
		c := decodeMinimWAFCorpusCase(t, func(m map[string]any) {
			request := jsonObjectOf(m["request"])
			request["body_base64"] = base64.StdEncoding.EncodeToString([]byte("ab"))
			request["body_repeat"] = 3
		})
		body, err := c.bodyBytes()
		require.NoError(t, err)
		assert.Equal(t, []byte("ababab"), body)
	})

	t.Run("empty body_base64 means no body", func(t *testing.T) {
		emptyCases := 0
		for _, c := range cases {
			if c.Request.BodyBase64 != "" {
				continue
			}
			emptyCases++
			body, err := c.bodyBytes()
			require.NoErrorf(t, err, "case %s", c.ID)
			assert.Nilf(t, body, "case %s body", c.ID)
			tc, err := c.testCase()
			require.NoErrorf(t, err, "case %s", c.ID)
			assert.Nilf(t, tc.Data, "case %s Data", c.ID)
		}
		assert.Positive(t, emptyCases)
	})

	t.Run("malformed-encoding bodies survive byte-exact", func(t *testing.T) {
		isolation, ok := byID["corpus-isolation-malformed-then-attack"]
		require.True(t, ok)
		body, err := isolation.bodyBytes()
		require.NoError(t, err)
		assert.Equal(t, "1f8b0800000000002669643d3127206f72202731273d2731", hex.EncodeToString(body))
		assert.True(t, bytes.HasPrefix(body, []byte{0x1f, 0x8b, 0x08}), "gzip magic must survive")
		assert.True(t, bytes.Contains(body, []byte("id=1' or '1'='1")), "SQL injection tail must survive unnormalised")

		truncated, ok := byID["corpus-fail-inspection"]
		require.True(t, ok)
		truncatedBody, err := truncated.bodyBytes()
		require.NoError(t, err)
		assert.Equal(t, "1f8b0800000000000000", hex.EncodeToString(truncatedBody))
		assert.False(t, bytes.Contains(truncatedBody, wafCorpusReplacementChar))
	})
}

// ——————————————————————————————————————————————————————————————
// Shared-seam runner (WAF-AB.contract.md "Shared test seam" and
// WAF-AB.corpus.md Sections 6, 7, and 9).

// Classifications, verbatim from WAF-AB.corpus.md Section 7.
const (
	wafClassPass               = "pass"
	wafClassUnexpectedFailure  = "unexpected_failure"
	wafClassUnsupportedFeature = "unsupported_feature"
	wafClassHostUnavailable    = "host_unavailable"
	wafClassNotApplicable      = "not_applicable"
)

// wafClassificationOrder is the fixed print order for classification counts.
var wafClassificationOrder = []string{
	wafClassPass,
	wafClassUnexpectedFailure,
	wafClassUnsupportedFeature,
	wafClassHostUnavailable,
	wafClassNotApplicable,
}

// wafCorpusFamilyOrder is the fixed print order for the per-family breakdown.
var wafCorpusFamilyOrder = []string{
	"920", "930", "931", "932", "933", "934",
	"941", "942", "943", "944", "none",
}

// wafTrackGlobalEnabled records that the Track boots the test gateway with
// its WAF global setting enabled. The global config keys land with the
// middleware-integration bead; until then no global gate exists, the global
// setting is implicitly on, and the per-API WAF configuration surface alone
// controls enablement.
const wafTrackGlobalEnabled = true

// wafTrackClaimedFeatures is the set of corpus required_features names this
// Track claims (WAF-AB.corpus.md Section 5). No engine beads have landed, so
// the Track claims none and every feature-declaring case classifies
// unsupported_feature with a recorded reason.
var wafTrackClaimedFeatures = map[string]struct{}{}

// wafUnclaimedFeatures returns the required_features names the Track does not
// claim, in declared order.
func wafUnclaimedFeatures(required []string) []string {
	var unclaimed []string
	for _, feature := range required {
		if _, ok := wafTrackClaimedFeatures[feature]; !ok {
			unclaimed = append(unclaimed, feature)
		}
	}
	return unclaimed
}

// wafTrackRulesLoaded reports the CRS rules active in the Track's engine
// configuration. No engine beads have landed, so zero rules are loaded and
// the digest covers the empty ruleset.
func wafTrackRulesLoaded() (count int, digest string) {
	return 0, wafCorpusSHA256Hex(nil)
}

// wafDecisionRecord carries the closed shared WAF log-contract fields the
// runner asserts on (WAF-AB.contract.md "Shared WAF log contract"): the
// decision, matched rule IDs, and anomaly score.
type wafDecisionRecord struct {
	Mode           string
	Path           string
	Verdict        string
	Enforced       bool
	AnomalyScore   *int
	MatchedRuleIDs []string
}

// wafTrackDecisionRecords returns the decision records observed for one
// corpus replay. The log-record bead wires emission; until then no records
// exist, so log_record:true expectations mismatch (stage-appropriate) and
// log_record:false runs never fail for emitting one.
func wafTrackDecisionRecords(_, _ string) []wafDecisionRecord {
	return nil
}

// wafUpstreamRecorder captures what the echo upstream received for the most
// recent replay. Replays are sequential and the gateway proxies
// synchronously, so a reset/read cycle attributes one observation per replay.
type wafUpstreamRecorder struct {
	mu       sync.Mutex
	hits     int
	path     string
	bodySize int
	bodySHA  string
}

func (r *wafUpstreamRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits, r.path, r.bodySize, r.bodySHA = 0, "", 0, ""
}

func (r *wafUpstreamRecorder) record(path string, body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits++
	if r.hits > 1 {
		return
	}
	r.path = path
	r.bodySize = len(body)
	r.bodySHA = wafCorpusSHA256Hex(body)
}

// snapshot returns hits plus the first received path, size, and digest.
func (r *wafUpstreamRecorder) snapshot() (hits int, path string, size int, sha string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits, r.path, r.bodySize, r.bodySHA
}

// wafReplayLog adapts testing.TB so ts.Run transport failures become
// host_unavailable evidence instead of failing the Go test; classification,
// not the framework, owns the verdict.
type wafReplayLog struct {
	testing.TB
	failures []string
}

func (l *wafReplayLog) Error(args ...any) { l.failures = append(l.failures, fmt.Sprint(args...)) }
func (l *wafReplayLog) Errorf(format string, args ...any) {
	l.failures = append(l.failures, fmt.Sprintf(format, args...))
}
func (l *wafReplayLog) Fatal(args ...any)                 { l.Error(args...) }
func (l *wafReplayLog) Fatalf(format string, args ...any) { l.Errorf(format, args...) }
func (l *wafReplayLog) Fail()                             { l.Error("Fail") }
func (l *wafReplayLog) FailNow()                          { l.Error("FailNow") }
func (l *wafReplayLog) Failed() bool                      { return len(l.failures) > 0 }

// wafModeObservation is the evidence one replay produced, restricted to the
// assertable seam surface: status, response body, upstream reachability, and
// recorded log effects.
type wafModeObservation struct {
	Mode               string
	Status             int
	UpstreamReached    bool
	UpstreamHits       int
	UpstreamPath       string
	UpstreamBodySHA256 string
	ExpectedBodySHA256 string
	ResponseBody       []byte
}

// wafObservedVerdict derives the on-the-wire verdict from status and upstream
// reachability. A CRS block returns 403 and a fail-closed internal failure
// returns 503, both without reaching upstream; everything else is allow.
func wafObservedVerdict(o wafModeObservation) (verdict string, enforced bool) {
	if !o.UpstreamReached && (o.Status == http.StatusForbidden || o.Status == http.StatusServiceUnavailable) {
		return "block", true
	}
	return "allow", false
}

// wafCompareModeExpectation compares one replay's evidence against its
// mode-keyed expectation and returns every mismatch reason. Per Section 6,
// anomaly_score and matched_rule_ids are checked when decision-record
// evidence is available; log_record true requires the record, log_record
// false never fails a run that emits one.
func wafCompareModeExpectation(mode string, exp wafCorpusExpectation, obs wafModeObservation, records []wafDecisionRecord) []string {
	var mismatches []string

	if obs.Status != exp.Status {
		mismatches = append(mismatches, fmt.Sprintf("status: got %d want %d", obs.Status, exp.Status))
	}
	if obs.UpstreamReached != exp.UpstreamReached {
		mismatches = append(mismatches, fmt.Sprintf("upstream_reached: got %t want %t", obs.UpstreamReached, exp.UpstreamReached))
	}

	verdict, enforced := wafObservedVerdict(obs)
	if verdict != exp.Verdict {
		mismatches = append(mismatches, fmt.Sprintf("verdict: got %s want %s", verdict, exp.Verdict))
	}
	if enforced != exp.Enforced {
		mismatches = append(mismatches, fmt.Sprintf("enforced: got %t want %t", enforced, exp.Enforced))
	}

	if mode == wafCorpusModeAudit {
		// Audit rule: upstream is reached, the status is unchanged from
		// no-WAF behaviour (carried by the status comparison above), and no
		// block is enforced.
		if !obs.UpstreamReached {
			mismatches = append(mismatches, "audit rule: upstream must be reached")
		}
		if enforced {
			mismatches = append(mismatches, "audit rule: no block may be enforced")
		}
	}

	if exp.BodyMatch != "" {
		re, err := regexp.Compile(exp.BodyMatch)
		if err != nil {
			mismatches = append(mismatches, fmt.Sprintf("body_match: bad pattern %q: %v", exp.BodyMatch, err))
		} else if !re.Match(obs.ResponseBody) {
			mismatches = append(mismatches, fmt.Sprintf("body_match: response body does not contain %q", exp.BodyMatch))
		}
	}

	if obs.UpstreamReached {
		// Body restoration: the upstream must receive the original bytes
		// unchanged, proven by digest against the loader-computed body.
		if obs.UpstreamBodySHA256 != obs.ExpectedBodySHA256 {
			mismatches = append(mismatches, fmt.Sprintf("body restoration: upstream received digest %s want %s", obs.UpstreamBodySHA256, obs.ExpectedBodySHA256))
		}
	}
	if obs.UpstreamReached && obs.UpstreamHits != 1 {
		mismatches = append(mismatches, fmt.Sprintf("upstream: expected exactly one upstream hit, got %d", obs.UpstreamHits))
	}

	if exp.LogRecord {
		if len(records) == 0 {
			mismatches = append(mismatches, "decision record: log_record=true but no decision record observed")
		} else {
			record := records[0]
			if record.Verdict != "block" && record.Verdict != "allow" {
				mismatches = append(mismatches, fmt.Sprintf("decision record: missing verdict, got %q", record.Verdict))
			}
			if record.MatchedRuleIDs == nil {
				mismatches = append(mismatches, "decision record: missing matched rule IDs")
			}
			if record.AnomalyScore == nil {
				mismatches = append(mismatches, "decision record: missing anomaly score")
			}
			if record.Verdict != exp.Verdict {
				mismatches = append(mismatches, fmt.Sprintf("decision record verdict: got %s want %s", record.Verdict, exp.Verdict))
			}
			if exp.MatchedRuleIDs != nil {
				matched := make(map[string]struct{}, len(record.MatchedRuleIDs))
				for _, id := range record.MatchedRuleIDs {
					matched[id] = struct{}{}
				}
				for _, id := range exp.MatchedRuleIDs.Required {
					if _, ok := matched[id]; !ok {
						mismatches = append(mismatches, fmt.Sprintf("matched rule IDs: required %s not matched", id))
					}
				}
				for _, id := range exp.MatchedRuleIDs.Forbidden {
					if _, ok := matched[id]; ok {
						mismatches = append(mismatches, fmt.Sprintf("matched rule IDs: forbidden %s matched", id))
					}
				}
			}
			if exp.AnomalyScore != nil && record.AnomalyScore != nil {
				score := *record.AnomalyScore
				if exp.AnomalyScore.Min != nil && score < *exp.AnomalyScore.Min {
					mismatches = append(mismatches, fmt.Sprintf("anomaly score: got %d want min %d", score, *exp.AnomalyScore.Min))
				}
				if exp.AnomalyScore.Max != nil && score > *exp.AnomalyScore.Max {
					mismatches = append(mismatches, fmt.Sprintf("anomaly score: got %d want max %d", score, *exp.AnomalyScore.Max))
				}
			}
		}
	}
	// log_record false: an emitted record never fails the run. No checks.

	return mismatches
}

// wafModeResult records one (case, mode) replay outcome.
type wafModeResult struct {
	Mode               string
	Status             int
	UpstreamReached    bool
	UpstreamBodySHA256 string
	ExpectedBodySHA256 string
	HostUnavailable    bool
	OK                 bool
	Mismatches         []string
}

// wafCaseResult records exactly one classification per corpus case plus the
// evidence behind it.
type wafCaseResult struct {
	ID        string
	Family    string
	Class     string
	Reason    string
	Unclaimed []string
	Modes     []wafModeResult
}

// wafCorpusReport is the per-run report required by WAF-AB.corpus.md
// Section 7: applicable pass count and rate, rules loaded with digest,
// deduplicated unsupported features, classification counts, and a
// per-family breakdown.
type wafCorpusReport struct {
	Total              int
	ApplicablePassed   int
	ApplicableExecuted int
	RulesLoaded        int
	RulesDigest        string
	Unsupported        []string
	Counts             map[string]int
	FamilyPass         map[string]int
	FamilyUnexpected   map[string]int
}

func (r *wafCorpusReport) String() string {
	rate := 0.0
	if r.ApplicableExecuted > 0 {
		rate = 100 * float64(r.ApplicablePassed) / float64(r.ApplicableExecuted)
	}

	features := "none"
	if len(r.Unsupported) > 0 {
		features = strings.Join(r.Unsupported, ", ")
	}

	lines := []string{
		"WAF shared corpus report",
		fmt.Sprintf("Applicable tests passed: %d/%d (%.1f%%)", r.ApplicablePassed, r.ApplicableExecuted, rate),
		fmt.Sprintf("Rules loaded: %d (digest %s)", r.RulesLoaded, r.RulesDigest),
		fmt.Sprintf("Unsupported features: %s", features),
		"Classification counts:",
	}
	for _, class := range wafClassificationOrder {
		lines = append(lines, fmt.Sprintf("  %s: %d", class, r.Counts[class]))
	}
	lines = append(lines, "Per-family breakdown:")
	for _, family := range wafCorpusFamilyOrder {
		lines = append(lines, fmt.Sprintf("  %s: pass=%d unexpected_failure=%d", family, r.FamilyPass[family], r.FamilyUnexpected[family]))
	}
	return strings.Join(lines, "\n") + "\n"
}

func buildWafCorpusReport(results []wafCaseResult) *wafCorpusReport {
	report := &wafCorpusReport{
		Total:            len(results),
		Counts:           make(map[string]int, len(wafClassificationOrder)),
		FamilyPass:       make(map[string]int, len(wafCorpusFamilyOrder)),
		FamilyUnexpected: make(map[string]int, len(wafCorpusFamilyOrder)),
	}
	for _, class := range wafClassificationOrder {
		report.Counts[class] = 0
	}

	unsupported := map[string]struct{}{}
	for _, result := range results {
		report.Counts[result.Class]++
		for _, feature := range result.Unclaimed {
			unsupported[feature] = struct{}{}
		}
		switch result.Class {
		case wafClassPass:
			report.FamilyPass[result.Family]++
		case wafClassUnexpectedFailure:
			report.FamilyUnexpected[result.Family]++
		}
	}

	report.Unsupported = make([]string, 0, len(unsupported))
	for feature := range unsupported {
		report.Unsupported = append(report.Unsupported, feature)
	}
	sort.Strings(report.Unsupported)

	report.ApplicablePassed = report.Counts[wafClassPass]
	report.ApplicableExecuted = report.Counts[wafClassPass] + report.Counts[wafClassUnexpectedFailure]
	report.RulesLoaded, report.RulesDigest = wafTrackRulesLoaded()
	return report
}

// runWAFSharedCorpus boots the test gateway with the WAF global setting
// enabled, builds one API per mode on the WAF configuration surface with a
// reachable echo upstream, replays every corpus case through ts.Run, and
// classifies each executed case exactly once.
func runWAFSharedCorpus(t *testing.T, corpusCases []wafCorpusCase) ([]wafCaseResult, *wafCorpusReport) {
	t.Helper()

	ts := StartTest(func(_ *config.Config) {
		// The WAF global gate lands with the middleware-integration bead's
		// config keys. Until then no global gate exists, the global setting
		// is implicitly enabled (wafTrackGlobalEnabled), and the per-API WAF
		// configuration surface alone controls enablement.
	})
	defer ts.Close()

	recorder := &wafUpstreamRecorder{}
	echo := func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		recorder.record(r.URL.Path, body)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(body); err != nil {
			return
		}
	}

	modes := []string{wafCorpusModeAudit, wafCorpusModeBlock}
	listenPath := map[string]string{
		wafCorpusModeAudit: "/waf-audit-mode",
		wafCorpusModeBlock: "/waf-block-mode",
	}
	upstreamKey := map[string]string{
		wafCorpusModeAudit: "waf-corpus-audit",
		wafCorpusModeBlock: "waf-corpus-block",
	}

	// Register the echo upstream for every (mode, case path) pair. With
	// StripListenPath the gateway forwards the stripped case path after the
	// mode's target path, so the root case "/" lands on the bare key and
	// every other case on key+path.
	for _, mode := range modes {
		for _, c := range corpusCases {
			key := upstreamKey[mode]
			if c.Request.Path != "/" {
				key += c.Request.Path
			}
			ts.AddDynamicHandler(key, echo)
		}
	}

	// One API per mode using the WAF configuration surface.
	apiGens := make([]func(spec *APISpec), 0, len(modes))
	for _, mode := range modes {
		apiGens = append(apiGens, func(spec *APISpec) {
			spec.APIID = "waf-corpus-" + mode
			spec.Name = "waf-corpus-" + mode
			spec.Proxy.ListenPath = listenPath[mode]
			spec.Proxy.TargetURL = TestHttpAny + "/" + upstreamKey[mode]
			spec.Proxy.StripListenPath = true
			if wafTrackGlobalEnabled {
				spec.WAF = apidef.WAFConfig{
					Enabled:   true,
					Mode:      mode,
					BodyLimit: wafRequestBodyLimit,
				}
			}
		})
	}
	for _, spec := range ts.Gw.BuildAndLoadAPI(apiGens...) {
		require.Emptyf(t, spec.WAF.Validate(), "API %s WAF config must validate", spec.APIID)
		assert.Equalf(t, spec.APIID, "waf-corpus-"+spec.WAF.EffectiveMode(), "API %s mode", spec.APIID)
	}

	results := make([]wafCaseResult, 0, len(corpusCases))
	for _, c := range corpusCases {
		result := wafCaseResult{ID: c.ID, Family: c.AttackFamily}

		switch {
		case !c.Applicable:
			result.Class = wafClassNotApplicable
			result.Reason = "applicable=false; skipped, never failed"
			results = append(results, result)
			continue

		case len(wafUnclaimedFeatures(c.RequiredFeatures)) > 0:
			unclaimed := wafUnclaimedFeatures(c.RequiredFeatures)
			result.Class = wafClassUnsupportedFeature
			result.Unclaimed = unclaimed
			result.Reason = fmt.Sprintf("required features not claimed by the Track: %s", strings.Join(unclaimed, ", "))
			if c.Request.Proto != "" && c.Request.Proto != "HTTP/1.1" {
				result.Reason += fmt.Sprintf("; request proto %s not drivable at the seam", c.Request.Proto)
			}
			results = append(results, result)
			continue

		case c.Request.Proto != "" && c.Request.Proto != "HTTP/1.1":
			// A protocol case without a declared protocol feature is still
			// classified with a recorded reason, never silently skipped.
			result.Class = wafClassUnsupportedFeature
			result.Reason = fmt.Sprintf("request proto %s not drivable at the seam", c.Request.Proto)
			results = append(results, result)
			continue
		}

		body, err := c.bodyBytes()
		if err != nil {
			result.Class = wafClassUnexpectedFailure
			result.Reason = fmt.Sprintf("harness: expanding body: %v", err)
			results = append(results, result)
			continue
		}

		tc, err := c.testCase()
		if err != nil {
			result.Class = wafClassUnexpectedFailure
			result.Reason = fmt.Sprintf("harness: building test case: %v", err)
			results = append(results, result)
			continue
		}

		hostUnavailable := ""
		for _, mode := range modes {
			modeResult := wafModeResult{Mode: mode, ExpectedBodySHA256: wafCorpusSHA256Hex(body)}

			recorder.reset()
			replayLog := &wafReplayLog{TB: t}
			tc.Path = listenPath[mode] + c.Request.Path
			resp, runErr := ts.Run(replayLog, tc)

			if runErr != nil {
				modeResult.HostUnavailable = true
				if hostUnavailable == "" {
					hostUnavailable = fmt.Sprintf("gateway or upstream unavailable in %s mode: %v", mode, runErr)
				}
				result.Modes = append(result.Modes, modeResult)
				continue
			}

			obs := wafModeObservation{
				Mode:               mode,
				ExpectedBodySHA256: modeResult.ExpectedBodySHA256,
			}
			if resp != nil {
				obs.Status = resp.StatusCode
				respBody, readErr := io.ReadAll(resp.Body)
				if readErr != nil {
					modeResult.Mismatches = append(modeResult.Mismatches, fmt.Sprintf("harness: reading response body: %v", readErr))
				}
				obs.ResponseBody = respBody
			}
			hits, upstreamPath, _, upstreamSHA := recorder.snapshot()
			obs.UpstreamHits = hits
			obs.UpstreamPath = upstreamPath
			obs.UpstreamReached = hits > 0
			if obs.UpstreamReached {
				obs.UpstreamBodySHA256 = upstreamSHA
			}

			// 502/504 mean the gateway or upstream was unreachable or timed
			// out; they are never corpus expectations.
			if obs.Status == http.StatusBadGateway || obs.Status == http.StatusGatewayTimeout {
				modeResult.HostUnavailable = true
				if hostUnavailable == "" {
					hostUnavailable = fmt.Sprintf("gateway or upstream unavailable in %s mode: status %d", mode, obs.Status)
				}
				result.Modes = append(result.Modes, modeResult)
				continue
			}

			if len(replayLog.failures) > 0 {
				modeResult.Mismatches = append(modeResult.Mismatches,
					fmt.Sprintf("harness: replay framework reported: %s", strings.Join(replayLog.failures, "; ")))
			}

			modeResult.Status = obs.Status
			modeResult.UpstreamReached = obs.UpstreamReached
			modeResult.UpstreamBodySHA256 = obs.UpstreamBodySHA256
			modeResult.Mismatches = append(modeResult.Mismatches,
				wafCompareModeExpectation(mode, c.Expectations[mode], obs, wafTrackDecisionRecords(c.Request.Path, mode))...)
			modeResult.OK = len(modeResult.Mismatches) == 0

			result.Modes = append(result.Modes, modeResult)
		}

		switch {
		case hostUnavailable != "":
			result.Class = wafClassHostUnavailable
			result.Reason = hostUnavailable
		case wafAllModesOK(result.Modes):
			result.Class = wafClassPass
		default:
			result.Class = wafClassUnexpectedFailure
			var mismatches []string
			for _, modeResult := range result.Modes {
				if len(modeResult.Mismatches) > 0 {
					mismatches = append(mismatches, fmt.Sprintf("[%s] %s", modeResult.Mode, strings.Join(modeResult.Mismatches, "; ")))
				}
			}
			result.Reason = strings.Join(mismatches, " | ")
		}

		if result.Class != wafClassPass {
			t.Logf("waf corpus: case %s classified %s: %s", result.ID, result.Class, result.Reason)
		}
		results = append(results, result)
	}

	return results, buildWafCorpusReport(results)
}

func wafAllModesOK(modeResults []wafModeResult) bool {
	if len(modeResults) == 0 {
		return false
	}
	for _, modeResult := range modeResults {
		if !modeResult.OK {
			return false
		}
	}
	return true
}

func TestWAFSharedCorpus(t *testing.T) {
	corpusCases, err := loadWAFCorpusFixture(wafCorpusDir(t))
	require.NoError(t, err)

	t.Run("mode and log-record expectation semantics", func(t *testing.T) {
		score := 7
		min := 5
		fullRecord := wafDecisionRecord{
			Mode:           wafCorpusModeAudit,
			Verdict:        "block",
			AnomalyScore:   &score,
			MatchedRuleIDs: []string{"920274"},
		}
		allowAll := wafCorpusExpectation{
			Verdict:         "allow",
			Enforced:        false,
			Status:          http.StatusOK,
			UpstreamReached: true,
		}
		passObs := wafModeObservation{
			Mode:               wafCorpusModeAudit,
			Status:             http.StatusOK,
			UpstreamReached:    true,
			UpstreamHits:       1,
			UpstreamBodySHA256: wafCorpusSHA256Hex(nil),
			ExpectedBodySHA256: wafCorpusSHA256Hex(nil),
		}

		t.Run("log_record true requires a decision record", func(t *testing.T) {
			exp := allowAll
			exp.LogRecord = true
			mismatches := wafCompareModeExpectation(wafCorpusModeAudit, exp, passObs, nil)
			assert.Contains(t, mismatchesString(mismatches), "decision record: log_record=true but no decision record observed")
		})

		t.Run("log_record false never fails a run that emits one", func(t *testing.T) {
			mismatches := wafCompareModeExpectation(wafCorpusModeAudit, allowAll, passObs, []wafDecisionRecord{fullRecord})
			assert.Empty(t, mismatches)
		})

		t.Run("the decision record carries verdict, matched rule IDs, and anomaly score", func(t *testing.T) {
			exp := wafCorpusExpectation{
				Verdict:         "block",
				Enforced:        true,
				Status:          http.StatusForbidden,
				UpstreamReached: false,
				LogRecord:       true,
				AnomalyScore:    &wafCorpusAnomalyScore{Min: &min},
				MatchedRuleIDs:  &wafCorpusMatchedRuleIDs{Required: []string{"920274"}},
			}
			blockedObs := wafModeObservation{Mode: wafCorpusModeBlock, Status: http.StatusForbidden, UpstreamReached: false}

			incomplete := wafDecisionRecord{Mode: wafCorpusModeBlock, Verdict: "block"}
			joined := mismatchesString(wafCompareModeExpectation(wafCorpusModeBlock, exp, blockedObs, []wafDecisionRecord{incomplete}))
			assert.Contains(t, joined, "decision record: missing matched rule IDs")
			assert.Contains(t, joined, "decision record: missing anomaly score")

			complete := wafCompareModeExpectation(wafCorpusModeBlock, exp, blockedObs, []wafDecisionRecord{fullRecord})
			assert.Empty(t, complete)
		})

		t.Run("matched rule IDs honour required and forbidden sets", func(t *testing.T) {
			exp := wafCorpusExpectation{
				Verdict:         "block",
				Enforced:        true,
				Status:          http.StatusForbidden,
				UpstreamReached: false,
				LogRecord:       true,
				MatchedRuleIDs:  &wafCorpusMatchedRuleIDs{Required: []string{"930120"}, Forbidden: []string{"920274"}},
			}
			blockedObs := wafModeObservation{Mode: wafCorpusModeBlock, Status: http.StatusForbidden, UpstreamReached: false}
			joined := mismatchesString(wafCompareModeExpectation(wafCorpusModeBlock, exp, blockedObs, []wafDecisionRecord{fullRecord}))
			assert.Contains(t, joined, "matched rule IDs: required 930120 not matched")
			assert.Contains(t, joined, "matched rule IDs: forbidden 920274 matched")
		})

		t.Run("audit rule requires upstream reach and no enforcement", func(t *testing.T) {
			blocked := passObs
			blocked.Status = http.StatusForbidden
			blocked.UpstreamReached = false
			blocked.UpstreamBodySHA256 = ""
			joined := mismatchesString(wafCompareModeExpectation(wafCorpusModeAudit, allowAll, blocked, nil))
			assert.Contains(t, joined, "audit rule: upstream must be reached")
			assert.Contains(t, joined, "audit rule: no block may be enforced")
		})

		t.Run("block-mode enforcement matches without a decision record", func(t *testing.T) {
			exp := wafCorpusExpectation{
				Verdict:         "block",
				Enforced:        true,
				Status:          http.StatusForbidden,
				UpstreamReached: false,
			}
			blocked := wafModeObservation{Mode: wafCorpusModeBlock, Status: http.StatusForbidden, UpstreamReached: false}
			assert.Empty(t, wafCompareModeExpectation(wafCorpusModeBlock, exp, blocked, nil))
		})

		t.Run("body restoration compares upstream digests with loader digests", func(t *testing.T) {
			tampered := passObs
			tampered.UpstreamBodySHA256 = wafCorpusSHA256Hex([]byte("tampered"))
			joined := mismatchesString(wafCompareModeExpectation(wafCorpusModeAudit, allowAll, tampered, nil))
			assert.Contains(t, joined, "body restoration: upstream received digest")
		})
	})

	results, report := runWAFSharedCorpus(t, corpusCases)
	t.Log("\n" + report.String())

	byID := make(map[string]wafCaseResult, len(results))
	for _, result := range results {
		byID[result.ID] = result
	}

	t.Run("every case is classified exactly once", func(t *testing.T) {
		require.Len(t, results, len(corpusCases))
		valid := map[string]struct{}{
			wafClassPass:               {},
			wafClassUnexpectedFailure:  {},
			wafClassUnsupportedFeature: {},
			wafClassHostUnavailable:    {},
			wafClassNotApplicable:      {},
		}
		for _, result := range results {
			assert.Containsf(t, valid, result.Class, "case %s classification %q outside the five-value enum", result.ID, result.Class)
		}
		for _, c := range corpusCases {
			_, ok := byID[c.ID]
			assert.Truef(t, ok, "case %s missing from results", c.ID)
		}
		total := 0
		for _, count := range report.Counts {
			total += count
		}
		assert.Equal(t, len(corpusCases), total, "classification counts must sum to the corpus size")
	})

	t.Run("stage-appropriate distribution while the Track claims no features", func(t *testing.T) {
		idsFor := func(class string) []string {
			var ids []string
			for _, result := range results {
				if result.Class == class {
					ids = append(ids, result.ID)
				}
			}
			return ids
		}

		// With no engine, only benign traffic matches expectations; every
		// executed attack expectation classifies unexpected_failure until
		// engine beads land.
		assert.ElementsMatch(t, []string{"corpus-benign-get"}, idsFor(wafClassPass))
		assert.ElementsMatch(t, []string{
			"corpus-920-host-ip",
			"corpus-930-lfi-passwd",
			"corpus-931-rfi-url",
			"corpus-933-php-wrapper",
			"corpus-934-nodejs-require",
			"corpus-943-session-fixation",
		}, idsFor(wafClassUnexpectedFailure))
		assert.Len(t, idsFor(wafClassUnsupportedFeature), len(corpusCases)-7)
		assert.Empty(t, idsFor(wafClassHostUnavailable))
		assert.Empty(t, idsFor(wafClassNotApplicable))
	})

	t.Run("report prints every required section", func(t *testing.T) {
		rendered := report.String()
		assert.Contains(t, rendered, "WAF shared corpus report")
		assert.Contains(t, rendered, "Applicable tests passed: 1/7 (14.3%)")
		assert.Contains(t, rendered, fmt.Sprintf("Rules loaded: 0 (digest %s)", wafCorpusSHA256Hex(nil)))

		assert.Contains(t, rendered, "Unsupported features:")
		for feature := range wafCorpusFeatureRegistry {
			assert.Containsf(t, rendered, feature, "every fixture feature must be reported")
		}

		assert.Contains(t, rendered, "Classification counts:")
		assert.Contains(t, rendered, "pass: 1")
		assert.Contains(t, rendered, "unexpected_failure: 6")
		assert.Contains(t, rendered, "unsupported_feature: 11")
		assert.Contains(t, rendered, "host_unavailable: 0")
		assert.Contains(t, rendered, "not_applicable: 0")

		assert.Contains(t, rendered, "Per-family breakdown:")
		assert.Contains(t, rendered, "920: pass=0 unexpected_failure=1")
		assert.Contains(t, rendered, "930: pass=0 unexpected_failure=1")
		assert.Contains(t, rendered, "931: pass=0 unexpected_failure=1")
		assert.Contains(t, rendered, "932: pass=0 unexpected_failure=0")
		assert.Contains(t, rendered, "933: pass=0 unexpected_failure=1")
		assert.Contains(t, rendered, "934: pass=0 unexpected_failure=1")
		assert.Contains(t, rendered, "941: pass=0 unexpected_failure=0")
		assert.Contains(t, rendered, "942: pass=0 unexpected_failure=0")
		assert.Contains(t, rendered, "943: pass=0 unexpected_failure=1")
		assert.Contains(t, rendered, "944: pass=0 unexpected_failure=0")
		assert.Contains(t, rendered, "none: pass=1 unexpected_failure=0")
	})

	t.Run("audit-mode expectations hold at the seam", func(t *testing.T) {
		benign := byID["corpus-benign-get"]
		require.Equal(t, wafClassPass, benign.Class)
		require.Len(t, benign.Modes, 2)

		audit := wafModeResultFor(t, benign.Modes, wafCorpusModeAudit)
		assert.True(t, audit.OK)
		assert.Equal(t, http.StatusOK, audit.Status)
		assert.True(t, audit.UpstreamReached, "audit mode must reach upstream")
		assert.False(t, audit.HostUnavailable)

		// Every executed attack case still reaches upstream in audit mode:
		// detection expectations fail, transport semantics must not.
		for _, id := range []string{
			"corpus-920-host-ip",
			"corpus-930-lfi-passwd",
			"corpus-931-rfi-url",
			"corpus-933-php-wrapper",
			"corpus-934-nodejs-require",
			"corpus-943-session-fixation",
		} {
			result := byID[id]
			require.Equalf(t, wafClassUnexpectedFailure, result.Class, "case %s", id)
			audit := wafModeResultFor(t, result.Modes, wafCorpusModeAudit)
			assert.Truef(t, audit.UpstreamReached, "case %s audit mode must reach upstream", id)
			assert.Equalf(t, http.StatusOK, audit.Status, "case %s audit status must be unchanged from no-WAF behaviour", id)
			assert.Contains(t, mismatchesString(audit.Mismatches), "decision record", "case %s audit log_record=true must require the decision record")
		}
	})

	t.Run("body restoration matches loader-computed digests", func(t *testing.T) {
		for _, result := range results {
			want, ok := wafCorpusBodyDigests[result.ID]
			require.Truef(t, ok, "no loader digest recorded for %s", result.ID)
			for _, modeResult := range result.Modes {
				assert.Equalf(t, want.sha256, modeResult.ExpectedBodySHA256, "case %s %s loader-computed digest", result.ID, modeResult.Mode)
				if modeResult.UpstreamReached {
					assert.Equalf(t, want.sha256, modeResult.UpstreamBodySHA256, "case %s %s upstream must receive original bytes unchanged", result.ID, modeResult.Mode)
				}
			}
		}
	})

	t.Run("protocol cases classify with a recorded reason", func(t *testing.T) {
		h2c := byID["corpus-h2c-upgrade"]
		assert.Equal(t, wafClassUnsupportedFeature, h2c.Class)
		assert.Contains(t, h2c.Reason, "h2c_upgrade")

		h2 := byID["corpus-tls-h2-benign"]
		assert.Equal(t, wafClassUnsupportedFeature, h2.Class)
		assert.Contains(t, h2.Reason, "http2_tls")
		assert.Contains(t, h2.Reason, "HTTP/2.0")

		assert.Contains(t, report.Unsupported, "h2c_upgrade")
		assert.Contains(t, report.Unsupported, "http2_tls")
	})
}

func wafModeResultFor(t *testing.T, modeResults []wafModeResult, mode string) wafModeResult {
	t.Helper()
	for _, modeResult := range modeResults {
		if modeResult.Mode == mode {
			return modeResult
		}
	}
	t.Fatalf("no result for mode %s", mode)
	return wafModeResult{}
}

func mismatchesString(mismatches []string) string {
	return strings.Join(mismatches, "; ")
}
