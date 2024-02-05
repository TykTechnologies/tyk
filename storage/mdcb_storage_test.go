package storage

import (
	"context"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestGetResourceType(t *testing.T) {
	tests := []struct {
		key      string
		expected string
	}{
		{"oauth-clientid.client-id", "Oauth Client"},
		{"cert.something", "certificate"},
		{"apikey.something", "api key"},
		{"unmatched-key", "key"},
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

	mdcb := NewMdcbStorage(localHandler, rpcHandler, log)

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
