package gateway

import (
	"net/url"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/stretchr/testify/assert"
)

func TestGetCoProcessGrpcServerTargetURL(t *testing.T) {
	tests := []struct {
		name                string
		coProcessGRPCServer string
		expectedURL         string
		expectError         bool
	}{
		{
			name:                "Invalid URL",
			coProcessGRPCServer: "://invalid",
			expectedURL:         "",
			expectError:         true,
		},
		{
			name:                "URL without tcp:// prefix",
			coProcessGRPCServer: "localhost:9000",
			expectedURL:         "localhost:9000",
			expectError:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a gateway instance with mock config
			gw := &Gateway{}

			// Set up the config with the test CoProcessGRPCServer value
			conf := config.Config{}
			conf.CoProcessOptions.CoProcessGRPCServer = tt.coProcessGRPCServer
			gw.SetConfig(conf)

			// Call the function being tested
			grpcURL, err := gw.GetCoProcessGrpcServerTargetURL()

			// Check if error matches expectation
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, grpcURL)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, grpcURL)
				assert.Equal(t, tt.expectedURL, grpcURL.String())
			}
		})
	}
}

func TestGetCoProcessGrpcServerTargetURLAsString(t *testing.T) {
	// Create a test URL
	testURL, _ := url.Parse("localhost:9000")

	// Call the function being tested
	result := GetCoProcessGrpcServerTargetUrlAsString(testURL)

	// Check the result
	assert.Equal(t, "localhost:9000", result)
}

func TestGetCoProcessGrpcServerTargetUrlAsString(t *testing.T) {
	assert.Equal(t, "localhost:3000", GetCoProcessGrpcServerTargetUrlAsString(&url.URL{Scheme: "tcp", Host: "localhost:3000"}))
}
