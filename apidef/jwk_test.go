package apidef

import (
	"testing"
	"time"

	tyktime "github.com/TykTechnologies/tyk/internal/time"
)

func TestJWK_GetCacheTimeoutSeconds(t *testing.T) {
	tests := []struct {
		name              string
		cacheTimeout      tyktime.ReadableDuration
		defaultExpiration int64
		expectedResult    int64
		description       string
	}{
		{
			name:              "5 minutes timeout",
			cacheTimeout:      tyktime.ReadableDuration(5 * time.Minute),
			defaultExpiration: 300,
			expectedResult:    300, // 5 * 60 seconds
			description:       "Should return 300 seconds for 5 minute timeout",
		},
		{
			name:              "30 seconds timeout",
			cacheTimeout:      tyktime.ReadableDuration(30 * time.Second),
			defaultExpiration: 300,
			expectedResult:    30,
			description:       "Should return 30 seconds for 30 second timeout",
		},
		{
			name:              "1 hour timeout",
			cacheTimeout:      tyktime.ReadableDuration(1 * time.Hour),
			defaultExpiration: 300,
			expectedResult:    3600, // 60 * 60 seconds
			description:       "Should return 3600 seconds for 1 hour timeout",
		},
		{
			name:              "2 hours 30 minutes timeout",
			cacheTimeout:      tyktime.ReadableDuration(2*time.Hour + 30*time.Minute),
			defaultExpiration: 300,
			expectedResult:    9000, // (2 * 60 + 30) * 60 seconds
			description:       "Should return 9000 seconds for 2h30m timeout",
		},
		{
			name:              "500 milliseconds timeout",
			cacheTimeout:      tyktime.ReadableDuration(500 * time.Millisecond),
			defaultExpiration: 300,
			expectedResult:    0, // Less than 1 second, rounds down to 0
			description:       "Should return 0 seconds for 500ms timeout (rounds down)",
		},
		{
			name:              "1.5 seconds timeout",
			cacheTimeout:      tyktime.ReadableDuration(1500 * time.Millisecond),
			defaultExpiration: 300,
			expectedResult:    1, // 1.5 seconds rounds down to 1
			description:       "Should return 1 second for 1.5s timeout (rounds down)",
		},
		{
			name:              "zero duration",
			cacheTimeout:      tyktime.ReadableDuration(0),
			defaultExpiration: 300,
			expectedResult:    300, // Should return default expiration
			description:       "Should return default expiration for zero duration",
		},
		{
			name:              "negative duration",
			cacheTimeout:      tyktime.ReadableDuration(-1 * time.Minute),
			defaultExpiration: 300,
			expectedResult:    300, // Should return default expiration
			description:       "Should return default expiration for negative duration",
		},
		{
			name:              "very small duration",
			cacheTimeout:      tyktime.ReadableDuration(1 * time.Nanosecond),
			defaultExpiration: 300,
			expectedResult:    0, // Less than 1 second, rounds down to 0
			description:       "Should return 0 for very small duration (rounds down)",
		},
		{
			name:              "zero default expiration",
			cacheTimeout:      tyktime.ReadableDuration(0),
			defaultExpiration: 0,
			expectedResult:    0, // Should return 0 when default is 0
			description:       "Should return 0 when default expiration is 0",
		},
		{
			name:              "large timeout with zero default",
			cacheTimeout:      tyktime.ReadableDuration(10 * time.Minute),
			defaultExpiration: 0,
			expectedResult:    600, // 10 * 60 seconds
			description:       "Should return 600 seconds for 10 minute timeout even with zero default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwk := &JWK{
				URL:          "https://example.com/jwks",
				CacheTimeout: tt.cacheTimeout,
			}

			result := jwk.GetCacheTimeoutSeconds(tt.defaultExpiration)

			if result != tt.expectedResult {
				t.Errorf("Expected %d, got %d. %s", tt.expectedResult, result, tt.description)
			}
		})
	}
}
