package storage

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"go.uber.org/mock/gomock"

	"github.com/TykTechnologies/tyk/storage/mock"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type testSetup struct {
	Logger      *logrus.Entry
	Local       *mock.MockHandler
	Remote      *mock.MockHandler
	MdcbStorage *MdcbStorage
	CleanUp     func()
}

var notFoundKeyErr = errors.New("key not found")

func getTestLogger() *logrus.Entry {
	logger := logrus.New()
	logger.Out = io.Discard
	log := logger.WithContext(context.Background())
	return log
}

func setupTest(t *testing.T) *testSetup {
	t.Helper() // Marks this function as a test helper
	log := getTestLogger()

	ctrlLocal := gomock.NewController(t)
	local := mock.NewMockHandler(ctrlLocal)

	ctrlRemote := gomock.NewController(t)
	remote := mock.NewMockHandler(ctrlRemote)

	mdcbStorage := NewMdcbStorage(local, remote, log, nil, nil, nil)

	cleanup := func() {
		ctrlLocal.Finish()
		ctrlRemote.Finish()
	}

	return &testSetup{
		Logger:      log,
		Local:       local,
		Remote:      remote,
		MdcbStorage: mdcbStorage,
		CleanUp:     cleanup,
	}
}

func TestGetResourceType(t *testing.T) {
	tests := []struct {
		key      string
		expected string
	}{
		{"oauth-clientid.client-id", resourceOauthClient},
		{"raw-something", resourceCertificate},
		{"apikey.something", resourceApiKey},
		{"unmatched-key", resourceKey},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := getResourceType(tt.key)
			if got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestMdcbStorage_GetMultiKey(t *testing.T) {
	rpcHandler := NewDummyStorage()
	err := rpcHandler.SetKey("key1", "1", 0)
	if err != nil {
		t.Error(err.Error())
	}

	localHandler := NewDummyStorage()
	err = localHandler.SetKey("key2", "1", 0)
	if err != nil {
		t.Error(err.Error())
	}
	err = localHandler.SetKey("key3", "1", 0)
	if err != nil {
		t.Error(err.Error())
	}

	logger := logrus.New()
	logger.Out = io.Discard
	log := logger.WithContext(context.Background())

	mdcb := NewMdcbStorage(localHandler, rpcHandler, log, nil, nil, nil)

	testsCases := []struct {
		name     string
		keyNames []string
		want     []string
		wantErr  bool
	}{
		{
			name:     "First key exists, pulled from RPC",
			keyNames: []string{"key1", "nonExistingKey"},
			want:     []string{"1"},
			wantErr:  false,
		},
		{
			name:     "First key exist, pulled from local storage",
			keyNames: []string{"key3", "nonExistingKey"},
			want:     []string{"1"},
			wantErr:  false,
		},
		{
			name:     "No keys exist",
			keyNames: []string{"nonExistingKey1", "nonExistingKey2"},
			want:     nil,
			wantErr:  true,
		},
	}

	for _, tc := range testsCases {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := mdcb.GetMultiKey(tc.keyNames)

			didErr := err != nil
			assert.Equal(t, tc.wantErr, didErr)
			assert.Equal(t, tc.want, keys)
		})
	}
}

func TestGetFromLocalStorage(t *testing.T) {
	setup := setupTest(t)
	defer setup.CleanUp()

	mdcb := setup.MdcbStorage
	setup.Local.EXPECT().GetKey("any").Return("exists", nil)
	setup.Local.EXPECT().GetKey("nonExistingKey").Return("", notFoundKeyErr)

	localVal, err := mdcb.getFromLocal("any")
	assert.Nil(t, err, "expected no error")
	assert.Equal(t, "exists", localVal)

	notFoundVal, err := mdcb.getFromLocal("nonExistingKey")
	assert.ErrorIs(t, err, notFoundKeyErr)
	assert.Equal(t, "", notFoundVal)
}

func TestGetFromRPCAndCache(t *testing.T) {
	setup := setupTest(t)
	defer setup.CleanUp()

	m := setup.MdcbStorage
	rpcHandler := setup.Remote

	// attempt with keys that do not follow pattern for oauth, certs, apikeys
	rpcHandler.EXPECT().GetKey("john").Return("doe", nil)
	rpcHandler.EXPECT().GetKey("jane").Return("", notFoundKeyErr)
	setup.Local.EXPECT().SetKey("john", gomock.Any(), gomock.Any()).Times(0)
	setup.Local.EXPECT().SetKey("jane", gomock.Any(), gomock.Any()).Times(0)

	rpcVal, err := m.getFromRPCAndCache("john")
	assert.Nil(t, err, "expected no error")
	assert.Equal(t, "doe", rpcVal)

	rpcVal, err = m.getFromRPCAndCache("jane")
	assert.Equal(t, "", rpcVal)
	assert.ErrorIs(t, err, notFoundKeyErr)

	// test oauth keys
	oauthClientKey := "oauth-clientid.my-client-id"
	rpcHandler.EXPECT().GetKey(oauthClientKey).Return("value", nil)
	setup.Local.EXPECT().SetKey(oauthClientKey, gomock.Any(), gomock.Any()).Times(1)
	rpcVal, err = m.getFromRPCAndCache(oauthClientKey)
	assert.Equal(t, "value", rpcVal)
	assert.Nil(t, err)

	// test certs keys
	// for certs we do not call directly the set key func, but the callback
	count := 0
	mockSaveCert := func(_, _ string) error {
		count++
		return nil
	}
	m.OnRPCCertPull = mockSaveCert

	certKey := "raw-my-cert-id"
	rpcHandler.EXPECT().GetKey(certKey).Return("value", nil)
	rpcVal, err = m.getFromRPCAndCache(certKey)
	assert.Equal(t, "value", rpcVal)
	assert.Equal(t, 1, count)
	assert.Nil(t, err)
}

func TestProcessResourceByType(t *testing.T) {
	// Setup

	errCachingFailed := errors.New("caching failed")
	// Test cases
	testCases := []struct {
		name          string
		key           string
		val           string
		setupMocks    func(handler *mock.MockHandler)
		expectedError error
	}{
		{
			name: "Successful OAuth client caching",
			key:  "oauth-clientid.client1",
			val:  "clientdata1",
			setupMocks: func(mockLocal *mock.MockHandler) {
				mockLocal.EXPECT().SetKey("oauth-clientid.client1", "clientdata1", gomock.Any()).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Failed OAuth client caching",
			key:  "oauth-clientid.failClient2",
			val:  "clientdata2",
			setupMocks: func(mockLocal *mock.MockHandler) {
				mockLocal.EXPECT().SetKey("oauth-clientid.failClient2", "clientdata2", gomock.Any()).Return(errCachingFailed)
			},
			expectedError: errCachingFailed,
		},
		{
			name: "Successful Certificate caching",
			key:  "raw-cert1",
			val:  "certdata1",
			setupMocks: func(_ *mock.MockHandler) {
				// Setup expectations for certificate caching if needed
			},
			expectedError: nil,
		},
		{
			name: "Failed Certificate caching",
			key:  "raw-failCert",
			val:  "certdata2",
			setupMocks: func(_ *mock.MockHandler) {
				// Setup expectations for failed certificate caching if needed
			},
			expectedError: errCachingFailed,
		},
		{
			name:          "Unknown resource type",
			key:           "unknown:resource1",
			val:           "data1",
			setupMocks:    func(_ *mock.MockHandler) {},
			expectedError: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setup := setupTest(t)
			defer setup.CleanUp()

			m := setup.MdcbStorage
			tc.setupMocks(setup.Local)

			// If testing certificate caching, setup the callback
			if strings.HasPrefix(tc.key, "raw-") {
				m.OnRPCCertPull = func(key, _ string) error {
					if key == "raw-failCert" {
						return errCachingFailed
					}
					return nil
				}
			}

			err := m.processResourceByType(tc.key, tc.val)

			if tc.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tc.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCacheOAuthClient(t *testing.T) {

	// Test cases
	testCases := []struct {
		name      string
		key       string
		val       string
		setKeyErr error
		expectLog bool
	}{
		{
			name:      "Successful cache",
			key:       "oauth1",
			val:       "clientdata1",
			setKeyErr: nil,
			expectLog: false,
		},
		{
			name:      "Cache failure",
			key:       "oauth2",
			val:       "clientdata2",
			setKeyErr: errors.New("failed to set key"),
			expectLog: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			setup := setupTest(t)
			defer setup.CleanUp()

			m := setup.MdcbStorage
			localHandler := setup.Local

			localHandler.EXPECT().SetKey(tc.key, tc.val, gomock.Any()).Return(tc.setKeyErr)
			err := m.cacheOAuthClient(tc.key, tc.val)

			if tc.setKeyErr != nil {
				assert.Error(t, err, "Should return an error when SetKey fails")
				assert.ErrorIs(t, tc.setKeyErr, err, "Returned error should match the SetKey error")
			} else {
				assert.NoError(t, err, "Should not return an error when SetKey succeeds")
			}

		})
	}
}

func TestCacheCertificate(t *testing.T) {

	// Test cases
	testCases := []struct {
		name              string
		key               string
		val               string
		callbackError     error
		shouldUseCallback bool
	}{
		{
			name:              "Successful cache",
			key:               "cert1",
			val:               "certdata1",
			callbackError:     nil,
			shouldUseCallback: true,
		},
		{
			name:              "Cache failure",
			key:               "cert2",
			val:               "certdata2",
			callbackError:     errors.New("failed to save"),
			shouldUseCallback: true,
		},
		{
			name:              "Nil callback",
			key:               "cert3",
			val:               "certdata3",
			callbackError:     nil,
			shouldUseCallback: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setup := setupTest(t)
			defer setup.CleanUp()

			m := setup.MdcbStorage

			var callbackCalled bool
			mockCallback := func(k, v string) error {
				callbackCalled = true
				assert.Equal(t, tc.key, k)
				assert.Equal(t, tc.val, v)
				return tc.callbackError
			}

			if tc.shouldUseCallback {
				m.OnRPCCertPull = mockCallback
			}

			// Call the method
			err := m.cacheCertificate(tc.key, tc.val)

			// Assertions
			if tc.shouldUseCallback {
				assert.True(t, callbackCalled, "Callback should have been called")
				if tc.callbackError != nil {
					assert.ErrorIs(t, tc.callbackError, err)
				}
			} else {
				assert.NoError(t, err)
				assert.False(t, callbackCalled, "Callback should not have been called")
			}

		})
	}
}
