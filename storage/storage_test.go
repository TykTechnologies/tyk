package storage

import "testing"

func Test_TokenOrg(t *testing.T) {
	tcs := []struct {
		name           string
		givenKey       string
		expectedResult string
	}{
		{
			name:           "long non-b64 key - without orgId ",
			givenKey:       "testdata-JJNIsqyZViCvcnbX8ouvG7yctsH1irHa2aklAFYC",
			expectedResult: "",
		},
		{
			name:           "b64 key",
			givenKey:       "eyJvcmciOiI2NDkyZjY2ZTZlYmJjNTZjNmE2YmYwMjIiLCJpZCI6IjEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU5IiwiaCI6Im11cm11cjY0In0=",
			expectedResult: "6492f66e6ebbc56c6a6bf022",
		},
		{
			name:           "long non-b64 key - with orgId",
			givenKey:       "6492f66e6ebbc56c6a6bf022657c162274933214b91ea570",
			expectedResult: "6492f66e6ebbc56c6a6bf022",
		},
		{
			name:           "short non-b64 key",
			givenKey:       "6492f66e6e",
			expectedResult: "",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			result := TokenOrg(tc.givenKey)
			if result != tc.expectedResult {
				t.Errorf("Expected %s, got %s", tc.expectedResult, result)
			}
		})
	}
}
