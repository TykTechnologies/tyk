package user

import (
	"encoding/json"
	"reflect"
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
