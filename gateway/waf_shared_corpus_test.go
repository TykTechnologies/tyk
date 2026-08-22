package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
