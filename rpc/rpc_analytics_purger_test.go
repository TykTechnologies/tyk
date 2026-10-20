package rpc

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/vmihailenco/msgpack.v2"

	"github.com/TykTechnologies/gorpc"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/storage"
)

func TestDecodeAnalyticsRecord(t *testing.T) {

	validRecord := analytics.AnalyticsRecord{
		Method: "POST",
	}
	validEncoded, err := msgpack.Marshal(&validRecord)
	assert.Nil(t, err)

	// Test cases
	testCases := []struct {
		name        string
		input       interface{}
		expectError bool
	}{
		{
			name: "Valid input",
			// convert to string so we emulate like reading from redis
			input:       string(validEncoded),
			expectError: false,
		},
		{
			name:        "Invalid input",
			input:       "invalidEncodedData",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeAnalyticsRecord(tc.input)

			if tc.expectError && err == nil {
				t.Error("Expected an error, but got none")
			}

			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestProcessAnalyticsValues(t *testing.T) {
	validRecord := analytics.AnalyticsRecord{
		Method: "POST",
	}
	validEncoded, err := msgpack.Marshal(&validRecord)
	assert.Nil(t, err)
	validEncodedAsString := string(validEncoded)

	// Test cases
	testCases := []struct {
		name            string
		analyticsValues []interface{}
		expectedLen     int
		expectError     bool
		failedRecords   int
	}{
		{
			name:            "Valid analytics values",
			analyticsValues: []interface{}{validEncodedAsString, validEncodedAsString},
			expectedLen:     2,
			failedRecords:   0,
			expectError:     false,
		},
		{
			name:            "Invalid analytics value",
			analyticsValues: []interface{}{validEncodedAsString, "invalidData"},
			expectedLen:     2,
			failedRecords:   1,
			expectError:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keys, failedRecords := processAnalyticsValues(tc.analyticsValues)
			assert.Equal(t, tc.failedRecords, failedRecords)
			assert.Equal(t, tc.expectedLen, len(keys))
		})
	}
}

func TestPurgeCacheRestoresDataOnRPCFailure(t *testing.T) {
	d := gorpc.NewDispatcher()
	d.AddFunc("Ping", func() bool {
		return true
	})
	purgeCalls := 0
	d.AddFunc("PurgeAnalyticsData", func(_ string) error {
		purgeCalls++
		return errors.New("mdcb unavailable")
	})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	server := gorpc.NewTCPServer(addr, d.NewHandlerFunc())
	server.LogError = gorpc.NilErrorLogger
	require.NoError(t, server.Start())
	defer server.Stop()

	client := gorpc.NewTCPClient(addr)
	client.LogError = gorpc.NilErrorLogger
	client.Start()
	defer client.Stop()

	origFuncClient := funcClientSingleton
	funcClientSingleton = d.NewFuncClient(client)
	values.clientIsConnected.Store(true)
	defer func() {
		funcClientSingleton = origFuncClient
		values.clientIsConnected.Store(false)
	}()

	store := &storage.RedisCluster{KeyPrefix: "analytics-", IsAnalytics: true, ConnectionHandler: rc}
	store.Connect()
	keyName := ANALYTICS_KEYNAME + "_0"
	defer store.DeleteKey(keyName)
	store.DeleteKey(keyName)

	record, err := msgpack.Marshal(&analytics.AnalyticsRecord{Method: "GET"})
	require.NoError(t, err)
	store.AppendToSetPipelined(keyName, [][]byte{record, record})

	purger := Purger{Store: store}
	purger.PurgeCache()

	assert.Equal(t, 1, purgeCalls)
	stored, err := store.GetListRange(keyName, 0, -1)
	require.NoError(t, err)
	assert.Len(t, stored, 2, "analytics records must be kept in redis when the RPC purge fails")
}
