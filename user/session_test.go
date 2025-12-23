package user

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/stretchr/testify/assert"
)

func TestSessionState_Touch_and_IsModified(t *testing.T) {
	result := NewSessionState()

	sess := NewSessionState()
	sess.OrgID = "tyk"

	// ensure session not modified
	assert.False(t, sess.IsModified())

	// modify session
	sess.Touch()
	assert.True(t, sess.IsModified())

	// encode session to json
	sb, err := json.Marshal(sess)
	assert.NoError(t, err)

	// decode session from json
	err = json.Unmarshal(sb, result)
	assert.NoError(t, err)

	// ensure session not modified
	assert.False(t, result.IsModified())
	assert.Equal(t, "tyk", result.OrgID)
}

func TestIsHashType(t *testing.T) {
	assert.False(t, IsHashType(""))
	assert.False(t, IsHashType("invalid"))
	valids := []string{"sha256", "bcrypt", "murmur32", "murmur64", "murmur128"}
	for _, ok := range valids {
		assert.True(t, IsHashType(ok))
	}
}

func TestSessionState_Lifetime(t *testing.T) {
	s := SessionState{}

	t.Run("forceGlobal=false", func(t *testing.T) {
		t.Run("respectExpiration=false", func(t *testing.T) {
			s.SessionLifetime = 1
			s.Expires = time.Now().Add(5 * time.Second).Unix()
			assert.Equal(t, int64(1), s.Lifetime(false, 2, false, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(2), s.Lifetime(false, 2, false, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(0), s.Lifetime(false, 0, false, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(0), s.Lifetime(false, -1, false, 3))

			assert.Equal(t, int64(1), s.Lifetime(false, 1, false, 0))
			assert.Equal(t, int64(0), s.Lifetime(false, 0, false, 0))
		})

		t.Run("respectExpiration=true", func(t *testing.T) {
			s.SessionLifetime = 1
			s.Expires = time.Now().Add(5 * time.Second).Unix()
			assert.Equal(t, int64(5), s.Lifetime(true, 2, false, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(5), s.Lifetime(true, 2, false, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(0), s.Lifetime(true, 0, false, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(0), s.Lifetime(true, -1, false, 3))

			assert.Equal(t, int64(6), s.Lifetime(true, 6, false, 7))
			assert.Equal(t, int64(0), s.Lifetime(true, 0, false, 7))
			assert.Equal(t, int64(5), s.Lifetime(true, 1, false, 0))

			s.Expires = 0
			assert.Equal(t, int64(0), s.Lifetime(true, 2, false, 3))
		})
	})

	t.Run("forceGlobal=true", func(t *testing.T) {
		t.Run("respectExpiration=false", func(t *testing.T) {
			s.SessionLifetime = 1
			assert.Equal(t, int64(3), s.Lifetime(false, 2, true, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(3), s.Lifetime(false, 2, true, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(3), s.Lifetime(false, 0, true, 3))
			assert.Equal(t, int64(0), s.Lifetime(false, 1, true, 0))
		})

		t.Run("respectExpiration=true", func(t *testing.T) {
			s.SessionLifetime = 1
			assert.Equal(t, int64(3), s.Lifetime(true, 2, true, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(3), s.Lifetime(true, 2, true, 3))

			s.SessionLifetime = 0
			assert.Equal(t, int64(3), s.Lifetime(true, 0, true, 3))
		})
	})
}

func Test_calculateLifetime(t *testing.T) {
	unixTime := func(t time.Duration) int64 {
		return time.Now().Add(t * time.Second).Unix()
	}

	t.Run("respectExpiration=false", func(t *testing.T) {
		assert.Equal(t, int64(3), calculateLifetime(false, unixTime(2), 3))
		assert.Equal(t, int64(2), calculateLifetime(false, unixTime(2), 2))
		assert.Equal(t, int64(1), calculateLifetime(false, unixTime(2), 1))
		assert.Equal(t, int64(0), calculateLifetime(false, unixTime(2), 0))
		assert.Equal(t, int64(-1), calculateLifetime(false, unixTime(2), -1))
		assert.Equal(t, int64(1), calculateLifetime(false, 0, 1))
		assert.Equal(t, int64(1), calculateLifetime(false, -1, 1))
	})

	t.Run("respectExpiration=true", func(t *testing.T) {
		assert.Equal(t, int64(3), calculateLifetime(true, unixTime(2), 3))
		assert.Equal(t, int64(2), calculateLifetime(true, unixTime(2), 2))
		assert.Equal(t, int64(2), calculateLifetime(true, unixTime(2), 1))
		assert.Equal(t, int64(0), calculateLifetime(true, unixTime(2), 0))
		assert.Equal(t, int64(-1), calculateLifetime(true, unixTime(2), -1))
		assert.Equal(t, int64(0), calculateLifetime(true, 0, 1))
		assert.Equal(t, int64(-1), calculateLifetime(true, -1, 1))
	})
}

func TestAPILimit_Duration(t *testing.T) {
	t.Run("valid limit", func(t *testing.T) {
		limit := APILimit{
			RateLimit: RateLimit{
				Rate: 1,
				Per:  2,
			},
		}
		expectedDuration := 2 * time.Second
		assert.Equal(t, expectedDuration, limit.Duration())
	})

	t.Run("Per is zero", func(t *testing.T) {
		limit := APILimit{
			RateLimit: RateLimit{
				Rate: 1,
				Per:  0,
			},
		}
		expectedDuration := time.Duration(0)
		assert.Equal(t, expectedDuration, limit.Duration())
	})

	t.Run("Rate is zero", func(t *testing.T) {
		limit := APILimit{
			RateLimit: RateLimit{
				Rate: 0,
				Per:  2,
			},
		}
		expectedDuration := time.Duration(0)
		assert.Equal(t, expectedDuration, limit.Duration())
	})
}

func TestAPILimit_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		input    APILimit
		expected bool
	}{
		{
			name: "All fields zero or empty",
			input: APILimit{
				RateLimit: RateLimit{
					Rate: 0,
					Per:  0,
				},
				ThrottleInterval:   0,
				ThrottleRetryLimit: 0,
				MaxQueryDepth:      0,
				QuotaMax:           0,
				QuotaRenews:        0,
				QuotaRemaining:     0,
				QuotaRenewalRate:   0,
				SetBy:              "",
			},
			expected: true,
		},
		{
			name: "Rate is non-zero",
			input: APILimit{
				RateLimit: RateLimit{
					Rate: 1,
				},
			},
			expected: false,
		},
		{
			name: "Per is non-zero",
			input: APILimit{
				RateLimit: RateLimit{
					Per: 1,
				},
			},
			expected: false,
		},
		{
			name: "ThrottleInterval is non-zero",
			input: APILimit{
				ThrottleInterval: 1,
			},
			expected: false,
		},
		{
			name: "ThrottleRetryLimit is non-zero",
			input: APILimit{
				ThrottleRetryLimit: 1,
			},
			expected: false,
		},
		{
			name: "MaxQueryDepth is non-zero",
			input: APILimit{
				MaxQueryDepth: 1,
			},
			expected: false,
		},
		{
			name: "QuotaMax is non-zero",
			input: APILimit{
				QuotaMax: 1,
			},
			expected: false,
		},
		{
			name: "QuotaRenews is non-zero",
			input: APILimit{
				QuotaRenews: 1,
			},
			expected: false,
		},
		{
			name: "QuotaRemaining is non-zero",
			input: APILimit{
				QuotaRemaining: 1,
			},
			expected: false,
		},
		{
			name: "QuotaRenewalRate is non-zero",
			input: APILimit{
				QuotaRenewalRate: 1,
			},
			expected: false,
		},
		{
			name: "SetBy is non-empty",
			input: APILimit{
				SetBy: "admin",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.input.IsEmpty())
		})
	}
}

func TestAPILimit_Clone(t *testing.T) {
	tests := []struct {
		name  string
		input APILimit
	}{
		{
			name: "All fields zero or empty",
			input: APILimit{
				RateLimit: RateLimit{
					Rate: 0,
					Per:  0,
				},
				ThrottleInterval:   0,
				ThrottleRetryLimit: 0,
				MaxQueryDepth:      0,
				QuotaMax:           0,
				QuotaRenews:        0,
				QuotaRemaining:     0,
				QuotaRenewalRate:   0,
				SetBy:              "",
			},
		},
		{
			name: "All fields set, no smoothing",
			input: APILimit{
				RateLimit: RateLimit{
					Rate: 100,
					Per:  60,
				},
				ThrottleInterval:   30,
				ThrottleRetryLimit: 5,
				MaxQueryDepth:      10,
				QuotaMax:           1000,
				QuotaRenews:        500,
				QuotaRemaining:     250,
				QuotaRenewalRate:   120,
				SetBy:              "user",
			},
		},
		{
			name: "All fields set with smoothing",
			input: APILimit{
				RateLimit: RateLimit{
					Rate: 100,
					Per:  60,
					Smoothing: &apidef.RateLimitSmoothing{
						Enabled:   true,
						Threshold: 50,
						Trigger:   80,
						Step:      10,
						Delay:     5,
					},
				},
				ThrottleInterval:   30,
				ThrottleRetryLimit: 5,
				MaxQueryDepth:      10,
				QuotaMax:           1000,
				QuotaRenews:        500,
				QuotaRemaining:     250,
				QuotaRenewalRate:   120,
				SetBy:              "user",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clone := tt.input.Clone()

			// Check that the cloned object is equal to the original
			if !reflect.DeepEqual(tt.input, *clone) {
				t.Errorf("Clone() = %v, want %v", clone, tt.input)
			}

			// Check that modifying the clone doesn't affect the original
			clone.Rate = 200
			assert.NotEqual(t, tt.input, clone)

			clone.SetBy = "modified"
			assert.NotEqual(t, tt.input, clone)

			if tt.input.Smoothing != nil {
				clone.Smoothing.Enabled = false
				assert.NotEqual(t, tt.input, clone)
			}
		})
	}
}

func TestEndpoints_Map(t *testing.T) {
	tests := []struct {
		name     string
		input    Endpoints
		expected EndpointsMap
	}{
		{
			name:     "Empty Endpoints",
			input:    Endpoints{},
			expected: nil,
		},
		{
			name: "Single Endpoint, Single Method",
			input: Endpoints{
				{
					Path: "/api/v1/users",
					Methods: EndpointMethods{
						{Name: "GET", Limit: RateLimit{Rate: 10, Per: 60}},
					},
				},
			},
			expected: map[string]RateLimit{
				"GET:/api/v1/users": {Rate: 10, Per: 60},
			},
		},
		{
			name: "Single Endpoint, Multiple Methods",
			input: Endpoints{
				{
					Path: "/api/v1/posts",
					Methods: EndpointMethods{
						{Name: "GET", Limit: RateLimit{Rate: 20, Per: 60}},
						{Name: "POST", Limit: RateLimit{Rate: 5, Per: 60}},
					},
				},
			},
			expected: map[string]RateLimit{
				"GET:/api/v1/posts":  {Rate: 20, Per: 60},
				"POST:/api/v1/posts": {Rate: 5, Per: 60},
			},
		},
		{
			name: "Multiple Endpoints, Multiple Methods",
			input: Endpoints{
				{
					Path: "/api/v1/users",
					Methods: EndpointMethods{
						{Name: "GET", Limit: RateLimit{Rate: 15, Per: 60}},
						{Name: "POST", Limit: RateLimit{Rate: 5, Per: 60}},
					},
				},
				{
					Path: "/api/v1/posts",
					Methods: EndpointMethods{
						{Name: "GET", Limit: RateLimit{Rate: 30, Per: 60}},
						{Name: "PUT", Limit: RateLimit{Rate: 10, Per: 60}},
					},
				},
			},
			expected: map[string]RateLimit{
				"GET:/api/v1/users":  {Rate: 15, Per: 60},
				"POST:/api/v1/users": {Rate: 5, Per: 60},
				"GET:/api/v1/posts":  {Rate: 30, Per: 60},
				"PUT:/api/v1/posts":  {Rate: 10, Per: 60},
			},
		},
		{
			name: "Duplicate Entries (Overwrite)",
			input: Endpoints{
				{
					Path: "/api/v1/users",
					Methods: EndpointMethods{
						{Name: "GET", Limit: RateLimit{Rate: 10, Per: 60}},
					},
				},
				{
					Path: "/api/v1/users",
					Methods: EndpointMethods{
						{Name: "GET", Limit: RateLimit{Rate: 20, Per: 60}},
					},
				},
			},
			expected: map[string]RateLimit{
				"GET:/api/v1/users": {Rate: 20, Per: 60},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.Map()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEndpointsMap_Endpoints(t *testing.T) {
	tests := []struct {
		name     string
		input    EndpointsMap
		expected Endpoints
	}{
		{
			name:     "Empty EndpointsMap",
			input:    EndpointsMap{},
			expected: nil,
		},
		{
			name: "Single Path, Single Method",
			input: EndpointsMap{
				"GET:/api/v1/users": RateLimit{Rate: 10, Per: 60},
			},
			expected: Endpoints{
				{
					Path: "/api/v1/users",
					Methods: EndpointMethods{
						{Name: "GET", Limit: RateLimit{Rate: 10, Per: 60}},
					},
				},
			},
		},
		{
			name: "Single Path, Multiple Methods",
			input: EndpointsMap{
				"GET:/api/v1/posts":  RateLimit{Rate: 20, Per: 60},
				"POST:/api/v1/posts": RateLimit{Rate: 5, Per: 60},
			},
			expected: Endpoints{
				{
					Path: "/api/v1/posts",
					Methods: EndpointMethods{
						{Name: "GET", Limit: RateLimit{Rate: 20, Per: 60}},
						{Name: "POST", Limit: RateLimit{Rate: 5, Per: 60}},
					},
				},
			},
		},
		{
			name: "Multiple Paths, Multiple Methods",
			input: EndpointsMap{
				"GET:/api/v1/users":  RateLimit{Rate: 15, Per: 60},
				"POST:/api/v1/users": RateLimit{Rate: 5, Per: 60},
				"GET:/api/v1/posts":  RateLimit{Rate: 30, Per: 60},
				"PUT:/api/v1/posts":  RateLimit{Rate: 10, Per: 60},
			},
			expected: Endpoints{
				{
					Path: "/api/v1/posts",
					Methods: EndpointMethods{
						{Name: "GET", Limit: RateLimit{Rate: 30, Per: 60}},
						{Name: "PUT", Limit: RateLimit{Rate: 10, Per: 60}},
					},
				},
				{
					Path: "/api/v1/users",
					Methods: EndpointMethods{
						{Name: "GET", Limit: RateLimit{Rate: 15, Per: 60}},
						{Name: "POST", Limit: RateLimit{Rate: 5, Per: 60}},
					},
				},
			},
		},
		{
			name: "Invalid Key Format",
			input: EndpointsMap{
				"GET:/api/v1/users":   RateLimit{Rate: 15, Per: 60},
				"invalid_key":         RateLimit{Rate: 5, Per: 60},
				"GET:/api/v1/posts":   RateLimit{Rate: 30, Per: 60},
				"PUT:/api/v1/posts":   RateLimit{Rate: 10, Per: 60},
				"another:invalid:key": RateLimit{Rate: 20, Per: 60},
			},
			expected: Endpoints{
				{
					Path: "/api/v1/posts",
					Methods: EndpointMethods{
						{Name: "GET", Limit: RateLimit{Rate: 30, Per: 60}},
						{Name: "PUT", Limit: RateLimit{Rate: 10, Per: 60}},
					},
				},
				{
					Path: "/api/v1/users",
					Methods: EndpointMethods{
						{Name: "GET", Limit: RateLimit{Rate: 15, Per: 60}},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.Endpoints()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// omitzero Serialization Tests
// =============================================================================

// TestSessionState_EmptySessionOmitsZeroFields verifies that an empty SessionState
// serializes to minimal JSON without zero-value fields.
func TestSessionState_EmptySessionOmitsZeroFields(t *testing.T) {
	session := &SessionState{}
	data, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("Failed to marshal empty session: %v", err)
	}

	jsonStr := string(data)

	// List of fields that should NOT appear in empty session JSON
	zeroFields := []string{
		"last_check",
		"allowance",
		"rate",
		"per",
		"date_created",
		"hmac_enabled",
		"quota_max",
		"quota_renews",
		"quota_remaining",
		"throttle_interval",
		"expires",
		"is_inactive",
		"enable_detail_recording",
		"enable_detailed_recording",
		"org_id",
		"oauth_client_id",
		"certificate",
		"hmac_string",
		"apply_policy_id",
		"alias",
	}

	for _, field := range zeroFields {
		if strings.Contains(jsonStr, `"`+field+`"`) {
			t.Errorf("Empty session JSON should not contain field %q, but got: %s", field, jsonStr)
		}
	}

	// Empty session should be just "{}" or very minimal
	if len(data) > 10 {
		t.Errorf("Empty session JSON should be minimal (expected ~2 bytes for '{}'), got %d bytes: %s", len(data), jsonStr)
	}
}

// TestSessionState_NonZeroFieldsPreserved verifies that non-zero fields are correctly serialized.
func TestSessionState_NonZeroFieldsPreserved(t *testing.T) {
	session := &SessionState{
		Rate:  100,
		Per:   60,
		OrgID: "org123",
	}

	data, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("Failed to marshal session: %v", err)
	}

	jsonStr := string(data)

	// These fields MUST be present
	requiredFields := map[string]string{
		`"rate":100`:        "rate",
		`"per":60`:          "per",
		`"org_id":"org123"`: "org_id",
	}

	for expected, fieldName := range requiredFields {
		if !strings.Contains(jsonStr, expected) {
			t.Errorf("JSON should contain %s (%s), got: %s", expected, fieldName, jsonStr)
		}
	}

	// These fields should NOT be present (they are zero/empty)
	absentFields := []string{
		"last_check",
		"quota_max",
		"hmac_enabled",
		"allowance",
		"expires",
	}

	for _, field := range absentFields {
		if strings.Contains(jsonStr, `"`+field+`"`) {
			t.Errorf("JSON should not contain unset field %q, got: %s", field, jsonStr)
		}
	}
}

// TestSessionState_ZeroTimeOmitted verifies that zero time.Time is omitted (key omitzero advantage).
func TestSessionState_ZeroTimeOmitted(t *testing.T) {
	session := &SessionState{
		DateCreated: time.Time{}, // Zero time
		Rate:        100,         // Set something so we have valid JSON
	}

	data, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("Failed to marshal session: %v", err)
	}

	jsonStr := string(data)

	// date_created should NOT appear (zero time is omitted with omitzero)
	if strings.Contains(jsonStr, "date_created") {
		t.Errorf("JSON should not contain date_created for zero time, got: %s", jsonStr)
	}

	// Specifically check that the "0001-01-01" timestamp does NOT appear
	// (this is the main advantage of omitzero over omitempty for time.Time)
	if strings.Contains(jsonStr, "0001-01-01") {
		t.Errorf("JSON should not contain '0001-01-01' timestamp, got: %s", jsonStr)
	}
}

// TestSessionState_NonZeroTimePreserved verifies that non-zero time.Time is correctly serialized.
func TestSessionState_NonZeroTimePreserved(t *testing.T) {
	now := time.Now()
	session := &SessionState{
		DateCreated: now,
	}

	data, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("Failed to marshal session: %v", err)
	}

	jsonStr := string(data)

	// date_created MUST be present
	if !strings.Contains(jsonStr, "date_created") {
		t.Errorf("JSON should contain date_created for non-zero time, got: %s", jsonStr)
	}

	// Verify it's a valid ISO-8601 timestamp (contains expected format elements)
	if !strings.Contains(jsonStr, fmt.Sprintf("%d-", now.Year())) {
		t.Errorf("JSON should contain valid year in date_created, got: %s", jsonStr)
	}

	// Unmarshal and verify the time is preserved
	var decoded SessionState
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal session: %v", err)
	}

	if decoded.DateCreated.IsZero() {
		t.Error("Decoded DateCreated should not be zero")
	}
}

// =============================================================================
// Compatibility Tests
// =============================================================================

// TestSessionState_BackwardCompatibility_OldFormatWithAllFields verifies that
// JSON with all fields (including zeros) deserializes correctly.
func TestSessionState_BackwardCompatibility_OldFormatWithAllFields(t *testing.T) {
	// Simulate old format with all fields present, including zeros
	oldFormatJSON := `{
		"last_check": 0,
		"allowance": 0,
		"rate": 100,
		"per": 60,
		"throttle_interval": 0,
		"throttle_retry_limit": 0,
		"max_query_depth": 0,
		"date_created": "0001-01-01T00:00:00Z",
		"expires": 0,
		"quota_max": 1000,
		"quota_renews": 0,
		"quota_remaining": 500,
		"quota_renewal_rate": 3600,
		"org_id": "test-org",
		"oauth_client_id": "",
		"oauth_keys": null,
		"certificate": "",
		"hmac_enabled": false,
		"enable_http_signature_validation": false,
		"hmac_string": "",
		"rsa_certificate_id": "",
		"is_inactive": false,
		"apply_policy_id": "",
		"apply_policies": null,
		"data_expires": 0,
		"enable_detail_recording": false,
		"enable_detailed_recording": false,
		"meta_data": null,
		"tags": null,
		"alias": "",
		"last_updated": "",
		"id_extractor_deadline": 0,
		"session_lifetime": 0,
		"smoothing": null
	}`

	var session SessionState
	err := json.Unmarshal([]byte(oldFormatJSON), &session)
	if err != nil {
		t.Fatalf("Failed to deserialize old format JSON: %v", err)
	}

	// Verify values are correctly loaded
	if session.Rate != 100 {
		t.Errorf("Expected Rate=100, got %v", session.Rate)
	}
	if session.Per != 60 {
		t.Errorf("Expected Per=60, got %v", session.Per)
	}
	if session.QuotaMax != 1000 {
		t.Errorf("Expected QuotaMax=1000, got %v", session.QuotaMax)
	}
	if session.QuotaRemaining != 500 {
		t.Errorf("Expected QuotaRemaining=500, got %v", session.QuotaRemaining)
	}
	if session.OrgID != "test-org" {
		t.Errorf("Expected OrgID='test-org', got %v", session.OrgID)
	}
	if session.HMACEnabled != false {
		t.Errorf("Expected HMACEnabled=false, got %v", session.HMACEnabled)
	}
	if session.LastCheck != 0 {
		t.Errorf("Expected LastCheck=0, got %v", session.LastCheck)
	}
}

// TestSessionState_ForwardCompatibility_NewCompactFormat verifies that
// compact JSON (only non-zero fields) deserializes correctly with proper defaults.
func TestSessionState_ForwardCompatibility_NewCompactFormat(t *testing.T) {
	// New compact format with only non-zero fields
	compactJSON := `{"rate":100,"per":60,"org_id":"org123"}`

	var session SessionState
	err := json.Unmarshal([]byte(compactJSON), &session)
	if err != nil {
		t.Fatalf("Failed to deserialize compact format JSON: %v", err)
	}

	// Verify non-zero values are loaded
	if session.Rate != 100 {
		t.Errorf("Expected Rate=100, got %v", session.Rate)
	}
	if session.Per != 60 {
		t.Errorf("Expected Per=60, got %v", session.Per)
	}
	if session.OrgID != "org123" {
		t.Errorf("Expected OrgID='org123', got %v", session.OrgID)
	}

	// Verify missing fields default to zero values
	if session.LastCheck != 0 {
		t.Errorf("Expected LastCheck to default to 0, got %v", session.LastCheck)
	}
	if session.HMACEnabled != false {
		t.Errorf("Expected HMACEnabled to default to false, got %v", session.HMACEnabled)
	}
	if !session.DateCreated.IsZero() {
		t.Errorf("Expected DateCreated.IsZero() to be true, got %v", session.DateCreated)
	}
	if session.QuotaMax != 0 {
		t.Errorf("Expected QuotaMax to default to 0, got %v", session.QuotaMax)
	}
	if session.AccessRights != nil {
		t.Errorf("Expected AccessRights to be nil, got %v", session.AccessRights)
	}
}

// =============================================================================
// IsZero Method Tests (for omitzero support)
// =============================================================================

// TestAPILimit_IsZero_EmptyLimit verifies that IsZero returns true for empty APILimit.
func TestAPILimit_IsZero_EmptyLimit(t *testing.T) {
	limit := APILimit{}

	if !limit.IsZero() {
		t.Error("Empty APILimit should return IsZero() == true")
	}
	if !limit.IsEmpty() {
		t.Error("Empty APILimit should return IsEmpty() == true")
	}
}

// TestAPILimit_IsZero_NonEmpty verifies that IsZero returns false when any field is set.
func TestAPILimit_IsZero_NonEmpty(t *testing.T) {
	tests := []struct {
		name  string
		limit APILimit
	}{
		{"Rate set", APILimit{RateLimit: RateLimit{Rate: 100}}},
		{"Per set", APILimit{RateLimit: RateLimit{Per: 60}}},
		{"QuotaMax set", APILimit{QuotaMax: 1000}},
		{"QuotaRemaining set", APILimit{QuotaRemaining: 500}},
		{"ThrottleInterval set", APILimit{ThrottleInterval: 10}},
		{"MaxQueryDepth set", APILimit{MaxQueryDepth: 5}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.limit.IsZero() {
				t.Errorf("APILimit with %s should return IsZero() == false", tt.name)
			}
		})
	}
}

// TestAccessDefinition_EmptyLimitOmitted verifies that empty Limit is omitted from JSON.
func TestAccessDefinition_EmptyLimitOmitted(t *testing.T) {
	session := &SessionState{
		Rate:  100,
		Per:   60,
		OrgID: "test",
		AccessRights: map[string]AccessDefinition{
			"api1": {
				APIID:    "api1",
				APIName:  "Test API",
				Versions: []string{"v1"},
				Limit:    APILimit{}, // Empty limit - should be omitted
			},
		},
	}

	data, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("Failed to marshal session: %v", err)
	}

	jsonStr := string(data)

	// Check that "limit":{} doesn't appear with empty values
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal for inspection: %v", err)
	}

	accessRights, ok := decoded["access_rights"].(map[string]interface{})
	if !ok {
		t.Fatal("access_rights not found or not a map")
	}

	api1, ok := accessRights["api1"].(map[string]interface{})
	if !ok {
		t.Fatal("api1 not found in access_rights")
	}

	// The "limit" key should not exist for empty APILimit
	if _, exists := api1["limit"]; exists {
		t.Errorf("Empty Limit should be omitted from JSON, got: %s", jsonStr)
	}
}

// TestRateLimit_IsZero verifies RateLimit.IsZero() behavior.
func TestRateLimit_IsZero(t *testing.T) {
	tests := []struct {
		name     string
		limit    RateLimit
		expected bool
	}{
		{"Empty", RateLimit{}, true},
		{"Rate set", RateLimit{Rate: 100}, false},
		{"Per set", RateLimit{Per: 60}, false},
		{"Both set", RateLimit{Rate: 100, Per: 60}, false},
		{"Smoothing set", RateLimit{Smoothing: &apidef.RateLimitSmoothing{Enabled: true}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.limit.IsZero(); got != tt.expected {
				t.Errorf("RateLimit.IsZero() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestBasicAuthData_IsZero verifies BasicAuthData.IsZero() behavior.
func TestBasicAuthData_IsZero(t *testing.T) {
	tests := []struct {
		name     string
		data     BasicAuthData
		expected bool
	}{
		{"Empty", BasicAuthData{}, true},
		{"Password set", BasicAuthData{Password: "secret"}, false},
		{"Hash set", BasicAuthData{Hash: HashBCrypt}, false},
		{"Both set", BasicAuthData{Password: "secret", Hash: HashBCrypt}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.data.IsZero(); got != tt.expected {
				t.Errorf("BasicAuthData.IsZero() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestJWTData_IsZero verifies JWTData.IsZero() behavior.
func TestJWTData_IsZero(t *testing.T) {
	tests := []struct {
		name     string
		data     JWTData
		expected bool
	}{
		{"Empty", JWTData{}, true},
		{"Secret set", JWTData{Secret: "my-secret"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.data.IsZero(); got != tt.expected {
				t.Errorf("JWTData.IsZero() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestMonitor_IsZero verifies Monitor.IsZero() behavior.
func TestMonitor_IsZero(t *testing.T) {
	tests := []struct {
		name     string
		monitor  Monitor
		expected bool
	}{
		{"Empty", Monitor{}, true},
		{"Nil TriggerLimits", Monitor{TriggerLimits: nil}, true},
		{"Empty TriggerLimits", Monitor{TriggerLimits: []float64{}}, true},
		{"With TriggerLimits", Monitor{TriggerLimits: []float64{0.5, 0.9}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.monitor.IsZero(); got != tt.expected {
				t.Errorf("Monitor.IsZero() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Performance Benchmarks
// =============================================================================

// createMinimalSession creates a session with minimal fields set.
func createMinimalSession() *SessionState {
	return &SessionState{
		Rate:  100,
		Per:   60,
		OrgID: "default",
		AccessRights: map[string]AccessDefinition{
			"api1": {
				APIID:    "api1",
				Versions: []string{"Default"},
			},
		},
	}
}

// createStandardSession creates a typical production session.
func createStandardSession() *SessionState {
	return &SessionState{
		Rate:             1000,
		Per:              60,
		Allowance:        1000,
		LastCheck:        time.Now().Unix(),
		QuotaMax:         10000,
		QuotaRemaining:   9500,
		QuotaRenewalRate: 3600,
		QuotaRenews:      time.Now().Add(time.Hour).Unix(),
		OrgID:            "org-123456",
		Expires:          time.Now().Add(365 * 24 * time.Hour).Unix(),
		ApplyPolicies:    []string{"policy-1", "policy-2"},
		Tags:             []string{"team:backend", "env:production", "tier:premium"},
		MetaData: map[string]interface{}{
			"user_id":    "usr-12345",
			"email":      "user@example.com",
			"department": "engineering",
		},
		AccessRights: map[string]AccessDefinition{
			"api1": {
				APIName:  "Users API",
				APIID:    "api1",
				Versions: []string{"v1", "v2"},
				Limit: APILimit{
					RateLimit: RateLimit{Rate: 500, Per: 60},
					QuotaMax:  5000,
				},
			},
			"api2": {
				APIName:  "Orders API",
				APIID:    "api2",
				Versions: []string{"v1"},
				Limit: APILimit{
					RateLimit: RateLimit{Rate: 200, Per: 60},
					QuotaMax:  2000,
				},
			},
			"api3": {
				APIName:  "Analytics API",
				APIID:    "api3",
				Versions: []string{"v1"},
			},
		},
	}
}

// createComplexSession creates a complex session with all features enabled.
func createComplexSession() *SessionState {
	return &SessionState{
		Rate:               5000,
		Per:                60,
		Allowance:          5000,
		LastCheck:          time.Now().Unix(),
		ThrottleInterval:   10,
		ThrottleRetryLimit: 3,
		MaxQueryDepth:      10,
		QuotaMax:           100000,
		QuotaRemaining:     95000,
		QuotaRenewalRate:   86400,
		QuotaRenews:        time.Now().Add(24 * time.Hour).Unix(),
		OrgID:              "org-enterprise-789",
		OauthClientID:      "oauth-client-12345",
		Expires:            time.Now().Add(365 * 24 * time.Hour).Unix(),
		DataExpires:        time.Now().Add(30 * 24 * time.Hour).Unix(),
		HMACEnabled:        true,
		HmacSecret:         "hmac-secret-key-12345",
		Certificate:        "-----BEGIN CERTIFICATE-----\nMIIC...(truncated)...\n-----END CERTIFICATE-----",
		ApplyPolicies:      []string{"policy-enterprise", "policy-analytics", "policy-admin"},
		Tags: []string{
			"team:platform",
			"env:production",
			"tier:enterprise",
			"region:us-east-1",
			"compliance:soc2",
		},
		MetaData: map[string]interface{}{
			"user_id":        "usr-enterprise-001",
			"email":          "admin@enterprise.com",
			"department":     "platform-engineering",
			"cost_center":    "cc-12345",
			"security_level": "high",
		},
		Monitor: Monitor{
			TriggerLimits: []float64{0.5, 0.75, 0.9, 0.95},
		},
		BasicAuthData: BasicAuthData{
			Password: "hashed-password-here",
			Hash:     HashBCrypt,
		},
		JWTData: JWTData{
			Secret: "jwt-secret-key-for-signing",
		},
		AccessRights: map[string]AccessDefinition{
			"api1": {
				APIName:  "Main API",
				APIID:    "api1",
				Versions: []string{"v1", "v2"},
				Limit: APILimit{
					RateLimit: RateLimit{Rate: 1000, Per: 60},
					QuotaMax:  50000,
				},
			},
			"api2": {
				APIName:  "Analytics API",
				APIID:    "api2",
				Versions: []string{"v1"},
				AllowedURLs: []AccessSpec{
					{URL: "/users/*", Methods: []string{"GET", "POST"}},
					{URL: "/orders/*", Methods: []string{"GET"}},
				},
				Limit: APILimit{
					RateLimit: RateLimit{Rate: 500, Per: 60},
					QuotaMax:  10000,
				},
			},
		},
	}
}

// BenchmarkSessionState_Marshal benchmarks JSON marshaling performance.
func BenchmarkSessionState_Marshal(b *testing.B) {
	sessions := map[string]*SessionState{
		"Empty":    {},
		"Minimal":  createMinimalSession(),
		"Standard": createStandardSession(),
		"Complex":  createComplexSession(),
	}

	for name, session := range sessions {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := json.Marshal(session)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSessionState_Unmarshal benchmarks JSON unmarshaling performance.
func BenchmarkSessionState_Unmarshal(b *testing.B) {
	sessions := map[string]*SessionState{
		"Empty":    {},
		"Minimal":  createMinimalSession(),
		"Standard": createStandardSession(),
		"Complex":  createComplexSession(),
	}

	for name, session := range sessions {
		data, err := json.Marshal(session)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var s SessionState
				err := json.Unmarshal(data, &s)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSessionState_RoundTrip benchmarks full marshal+unmarshal cycle.
func BenchmarkSessionState_RoundTrip(b *testing.B) {
	sessions := map[string]*SessionState{
		"Empty":    {},
		"Minimal":  createMinimalSession(),
		"Standard": createStandardSession(),
		"Complex":  createComplexSession(),
	}

	for name, session := range sessions {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				data, err := json.Marshal(session)
				if err != nil {
					b.Fatal(err)
				}
				var s SessionState
				err = json.Unmarshal(data, &s)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
