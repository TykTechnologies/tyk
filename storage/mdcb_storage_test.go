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

	mdcbStorage := NewMdcbStorage(local, remote, log, nil)

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

// Verifies: STK-REQ-098, SYS-REQ-186, SW-REQ-173
// STK-REQ-098:STK-REQ-098-AC-01:acceptance
// STK-REQ-098:error_handling:negative
// SYS-REQ-186:nominal:nominal
// SYS-REQ-186:boundary:nominal
// SYS-REQ-186:error_handling:nominal
// SYS-REQ-186:error_handling:negative
// SYS-REQ-186:encoding_safety:nominal
// SYS-REQ-186:determinism:nominal
// SW-REQ-173:nominal:nominal
// SW-REQ-173:boundary:nominal
// SW-REQ-173:error_handling:nominal
// SW-REQ-173:error_handling:negative
// SW-REQ-173:encoding_safety:nominal
// SW-REQ-173:determinism:nominal
func TestMdcbStorageAcceptance(t *testing.T) {
	localHandler := NewDummyStorage()
	rpcHandler := NewDummyStorage()
	mdcb := NewMdcbStorage(localHandler, rpcHandler, getTestLogger(), nil)

	assert.NoError(t, localHandler.SetKey("local-key", "local-value", 0))
	assert.NoError(t, rpcHandler.SetKey("rpc-key", "rpc-value", 0))

	value, err := mdcb.GetKey("local-key")
	assert.NoError(t, err)
	assert.Equal(t, "local-value", value)

	value, err = mdcb.GetKey("rpc-key")
	assert.NoError(t, err)
	assert.Equal(t, "rpc-value", value)

	assert.NoError(t, rpcHandler.SetKey("oauth-clientid.client", "oauth-value", 0))
	value, err = mdcb.GetKey("oauth-clientid.client")
	assert.NoError(t, err)
	assert.Equal(t, "oauth-value", value)

	cachedOAuth, err := localHandler.GetKey("oauth-clientid.client")
	assert.NoError(t, err)
	assert.Equal(t, "oauth-value", cachedOAuth)

	var certPulls int
	mdcb.OnRPCCertPull = func(key, val string) error {
		certPulls++
		assert.Equal(t, "raw-cert", key)
		assert.Equal(t, "cert-value", val)
		return nil
	}
	assert.NoError(t, rpcHandler.SetKey("raw-cert", "cert-value", 0))
	value, err = mdcb.GetKey("raw-cert")
	assert.NoError(t, err)
	assert.Equal(t, "cert-value", value)
	assert.Equal(t, 1, certPulls)

	assert.NoError(t, mdcb.SetKey("write-local", "write-value", 0))
	value, err = localHandler.GetKey("write-local")
	assert.NoError(t, err)
	assert.Equal(t, "write-value", value)

	assert.True(t, mdcb.DeleteKey("write-local"))
	assert.False(t, mdcb.DeleteKey("missing-key"))
	assert.True(t, mdcb.Connect())

	mdcb.AppendToSet("shared-list", "one")
	mdcb.AppendToSet("shared-list", "two")
	localValues, err := localHandler.GetListRange("shared-list", 0, 10)
	assert.NoError(t, err)
	assert.Equal(t, []string{"one", "two"}, localValues)

	rpcValues, err := rpcHandler.GetListRange("shared-list", 0, 10)
	assert.NoError(t, err)
	assert.Equal(t, []string{"one", "two"}, rpcValues)

	assert.PanicsWithValue(t, "implement me", func() {
		_, _ = mdcb.GetRawKey("unsupported")
	})
}

// Verifies: STK-REQ-098, SYS-REQ-186, SW-REQ-173
// STK-REQ-098:STK-REQ-098-AC-01:acceptance
// SYS-REQ-186:nominal:nominal
// SYS-REQ-186:boundary:nominal
// SYS-REQ-186:error_handling:nominal
// SYS-REQ-186:encoding_safety:nominal
// SYS-REQ-186:determinism:nominal
// SW-REQ-173:nominal:nominal
// SW-REQ-173:boundary:nominal
// SW-REQ-173:error_handling:nominal
// SW-REQ-173:encoding_safety:nominal
// SW-REQ-173:determinism:nominal
// MCDC SYS-REQ-186: storage_mdcb_construction_determined=T, storage_mdcb_local_rpc_reads_determined=T, storage_mdcb_resource_cache_determined=T, storage_mdcb_local_write_determined=T, storage_mdcb_key_collection_delegation_determined=T, storage_mdcb_list_membership_determined=T, storage_mdcb_connect_determined=T, storage_mdcb_unsupported_panics_determined=T => TRUE
// MCDC SW-REQ-173: storage_mdcb_construction_determined=T, storage_mdcb_local_rpc_reads_determined=T, storage_mdcb_resource_cache_determined=T, storage_mdcb_local_write_determined=T, storage_mdcb_key_collection_delegation_determined=T, storage_mdcb_list_membership_determined=T, storage_mdcb_connect_determined=T, storage_mdcb_unsupported_panics_determined=T => TRUE
func TestMdcbStorageReqProof(t *testing.T) {
	localHandler := NewDummyStorage()
	rpcHandler := NewDummyStorage()
	logger := getTestLogger()
	var certPulls int
	mdcb := NewMdcbStorage(localHandler, rpcHandler, logger, func(key, val string) error {
		certPulls++
		assert.Equal(t, "raw-cert", key)
		assert.Equal(t, "cert-value", val)
		return nil
	})

	assert.Equal(t, localHandler, mdcb.local)
	assert.Equal(t, rpcHandler, mdcb.rpc)
	assert.Equal(t, logger, mdcb.logger)
	assert.NotNil(t, mdcb.OnRPCCertPull)
	assert.True(t, mdcb.Connect())

	assert.NoError(t, localHandler.SetKey("local-key", "local-value", 0))
	assert.NoError(t, rpcHandler.SetKey("rpc-key", "rpc-value", 0))
	assert.NoError(t, rpcHandler.SetKey("oauth-clientid.client", "oauth-value", 0))
	assert.NoError(t, rpcHandler.SetKey("raw-cert", "cert-value", 0))

	value, err := mdcb.GetKey("local-key")
	assert.NoError(t, err)
	assert.Equal(t, "local-value", value)

	value, err = mdcb.GetKey("rpc-key")
	assert.NoError(t, err)
	assert.Equal(t, "rpc-value", value)

	values, err := mdcb.GetMultiKey([]string{"missing", "rpc-key"})
	assert.NoError(t, err)
	assert.Equal(t, []string{"rpc-value"}, values)

	_, err = mdcb.GetMultiKey([]string{"missing-a", "missing-b"})
	assert.Error(t, err)

	assert.Equal(t, resourceOauthClient, getResourceType("oauth-clientid.client"))
	assert.Equal(t, resourceCertificate, getResourceType("raw-cert"))
	assert.Equal(t, resourceApiKey, getResourceType("apikey.value"))
	assert.Equal(t, resourceKey, getResourceType("ordinary-key"))

	value, err = mdcb.GetKey("oauth-clientid.client")
	assert.NoError(t, err)
	assert.Equal(t, "oauth-value", value)
	cachedOAuth, err := localHandler.GetKey("oauth-clientid.client")
	assert.NoError(t, err)
	assert.Equal(t, "oauth-value", cachedOAuth)

	value, err = mdcb.GetKey("raw-cert")
	assert.NoError(t, err)
	assert.Equal(t, "cert-value", value)
	assert.Equal(t, 1, certPulls)

	assert.NoError(t, mdcb.SetKey("write-local", "write-value", 0))
	value, err = localHandler.GetKey("write-local")
	assert.NoError(t, err)
	assert.Equal(t, "write-value", value)
	_, err = rpcHandler.GetKey("write-local")
	assert.EqualError(t, err, "Not found")

	assert.True(t, mdcb.DeleteKey("write-local"))
	assert.False(t, mdcb.DeleteKey("missing-key"))

	assert.NoError(t, localHandler.SetKey("local-list-key", "value", 0))
	assert.Equal(t, []string{"local-key", "local-list-key", "oauth-clientid.client"}, sortedDummyKeys(mdcb.GetKeys("*")))
	assert.True(t, localHandler.DeleteScanMatch("*"))
	assert.Equal(t, []string{"oauth-clientid.client", "raw-cert", "rpc-key"}, sortedDummyKeys(mdcb.GetKeys("*")))
	assert.True(t, mdcb.DeleteScanMatch("*"))
	assert.Nil(t, mdcb.GetKeys("prefix*"))

	mdcb.AppendToSet("shared-list", "one")
	mdcb.AppendToSet("shared-list", "two")
	listValues, err := mdcb.GetListRange("shared-list", 0, 10)
	assert.NoError(t, err)
	assert.Equal(t, []string{"one", "two"}, listValues)

	exists, err := mdcb.Exists("shared-list")
	assert.NoError(t, err)
	assert.True(t, exists)

	assert.NoError(t, mdcb.RemoveFromList("shared-list", "one"))
	listValues, err = mdcb.GetListRange("shared-list", 0, 10)
	assert.NoError(t, err)
	assert.Equal(t, []string{"two"}, listValues)

	t.Run("delegated key and set operations", func(t *testing.T) {
		setup := setupTest(t)
		defer setup.CleanUp()

		filtered := map[string]string{"key": "value"}
		setup.Local.EXPECT().GetKeysAndValuesWithFilter("prefix").Return(filtered)
		assert.Equal(t, filtered, setup.MdcbStorage.GetKeysAndValuesWithFilter("prefix"))

		setup.Local.EXPECT().AddToSet("set-key", "value")
		setup.MdcbStorage.AddToSet("set-key", "value")

		setup.Local.EXPECT().RemoveFromSet("set-key", "value")
		setup.MdcbStorage.RemoveFromSet("set-key", "value")

		setup.Local.EXPECT().GetSet("set-key").Return(nil, errors.New("local miss"))
		setup.Remote.EXPECT().GetSet("set-key").Return(map[string]string{"rpc": "value"}, nil)
		got, err := setup.MdcbStorage.GetSet("set-key")
		assert.NoError(t, err)
		assert.Equal(t, map[string]string{"rpc": "value"}, got)

		setup.Local.EXPECT().SetKey("key", "value", int64(10)).Return(errors.New("write failed"))
		assert.EqualError(t, setup.MdcbStorage.SetKey("key", "value", 10), "cannot save key in local")
	})

	t.Run("delegated list and connection operations", func(t *testing.T) {
		setup := setupTest(t)
		defer setup.CleanUp()

		setup.Local.EXPECT().GetListRange("list-key", int64(0), int64(2)).Return(nil, errors.New("local miss"))
		setup.Remote.EXPECT().GetListRange("list-key", int64(0), int64(2)).Return([]string{"fallback"}, nil)
		got, err := setup.MdcbStorage.GetListRange("list-key", 0, 2)
		assert.NoError(t, err)
		assert.Equal(t, []string{"fallback"}, got)

		setup.Local.EXPECT().RemoveFromList("list-key", "value").Return(errors.New("local failed"))
		setup.Remote.EXPECT().RemoveFromList("list-key", "value").Return(nil)
		assert.NoError(t, setup.MdcbStorage.RemoveFromList("list-key", "value"))

		setup.Local.EXPECT().Exists("key").Return(false, errors.New("local failed"))
		setup.Remote.EXPECT().Exists("key").Return(false, errors.New("rpc failed"))
		exists, err := setup.MdcbStorage.Exists("key")
		assert.EqualError(t, err, "cannot find key in storages")
		assert.False(t, exists)

		setup.Local.EXPECT().Connect().Return(true)
		setup.Remote.EXPECT().Connect().Return(false)
		assert.False(t, setup.MdcbStorage.Connect())
	})

	unsupportedCases := []struct {
		name string
		run  func()
	}{
		{name: "GetRawKey", run: func() { _, _ = mdcb.GetRawKey("key") }},
		{name: "SetRawKey", run: func() { _ = mdcb.SetRawKey("key", "value", 0) }},
		{name: "SetExp", run: func() { _ = mdcb.SetExp("key", 0) }},
		{name: "GetExp", run: func() { _, _ = mdcb.GetExp("key") }},
		{name: "DeleteAllKeys", run: func() { _ = mdcb.DeleteAllKeys() }},
		{name: "DeleteRawKey", run: func() { _ = mdcb.DeleteRawKey("key") }},
		{name: "DeleteRawKeys", run: func() { _ = mdcb.DeleteRawKeys([]string{"key"}) }},
		{name: "GetKeysAndValues", run: func() { _ = mdcb.GetKeysAndValues() }},
		{name: "DeleteKeys", run: func() { _ = mdcb.DeleteKeys([]string{"key"}) }},
		{name: "Decrement", run: func() { mdcb.Decrement("key") }},
		{name: "IncrememntWithExpire", run: func() { _ = mdcb.IncrememntWithExpire("key", 0) }},
		{name: "SetRollingWindow", run: func() { _, _ = mdcb.SetRollingWindow("key", 1, "value", false) }},
		{name: "GetRollingWindow", run: func() { _, _ = mdcb.GetRollingWindow("key", 1, false) }},
		{name: "GetAndDeleteSet", run: func() { _ = mdcb.GetAndDeleteSet("key") }},
		{name: "GetKeyPrefix", run: func() { _ = mdcb.GetKeyPrefix() }},
		{name: "AddToSortedSet", run: func() { mdcb.AddToSortedSet("key", "value", 1) }},
		{name: "GetSortedSetRange", run: func() { _, _, _ = mdcb.GetSortedSetRange("key", "0", "1") }},
		{name: "RemoveSortedSetRange", run: func() { _ = mdcb.RemoveSortedSetRange("key", "0", "1") }},
	}

	for _, tc := range unsupportedCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.PanicsWithValue(t, "implement me", tc.run)
		})
	}
}

// Verifies: STK-REQ-098, SYS-REQ-186, SW-REQ-173
// SW-REQ-173:nominal:nominal
// SW-REQ-173:boundary:nominal
// SW-REQ-173:error_handling:nominal
// SW-REQ-173:error_handling:negative
// SW-REQ-173:encoding_safety:nominal
// SW-REQ-173:determinism:nominal
func TestMdcbStorageWrapperMethods(t *testing.T) {
	t.Run("SetKey writes local only and maps local write errors", func(t *testing.T) {
		setup := setupTest(t)
		defer setup.CleanUp()

		setup.Local.EXPECT().SetKey("key", "value", int64(10)).Return(nil)
		assert.NoError(t, setup.MdcbStorage.SetKey("key", "value", 10))

		setup = setupTest(t)
		defer setup.CleanUp()

		setup.Local.EXPECT().SetKey("key", "value", int64(10)).Return(errors.New("write failed"))
		assert.EqualError(t, setup.MdcbStorage.SetKey("key", "value", 10), "cannot save key in local")
	})

	t.Run("GetKeys uses local values before RPC fallback", func(t *testing.T) {
		setup := setupTest(t)
		defer setup.CleanUp()

		setup.Local.EXPECT().GetKeys("prefix*").Return([]string{"local"})
		assert.Equal(t, []string{"local"}, setup.MdcbStorage.GetKeys("prefix*"))

		setup = setupTest(t)
		defer setup.CleanUp()

		setup.Local.EXPECT().GetKeys("prefix*").Return(nil)
		setup.Remote.EXPECT().GetKeys("prefix*").Return([]string{"remote"})
		assert.Equal(t, []string{"remote"}, setup.MdcbStorage.GetKeys("prefix*"))

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		remote := mock.NewMockHandler(ctrl)
		remote.EXPECT().GetKeys("prefix*").Return([]string{"remote-only"})
		mdcb := NewMdcbStorage(nil, remote, getTestLogger(), nil)
		assert.Equal(t, []string{"remote-only"}, mdcb.GetKeys("prefix*"))
	})

	t.Run("DeleteKey and DeleteScanMatch combine local and RPC results", func(t *testing.T) {
		setup := setupTest(t)
		defer setup.CleanUp()

		setup.Local.EXPECT().DeleteKey("key").Return(false)
		setup.Remote.EXPECT().DeleteKey("key").Return(true)
		assert.True(t, setup.MdcbStorage.DeleteKey("key"))

		setup.Local.EXPECT().DeleteScanMatch("prefix*").Return(false)
		setup.Remote.EXPECT().DeleteScanMatch("prefix*").Return(false)
		assert.False(t, setup.MdcbStorage.DeleteScanMatch("prefix*"))
	})

	t.Run("Connect requires local and RPC connections", func(t *testing.T) {
		setup := setupTest(t)
		defer setup.CleanUp()

		setup.Local.EXPECT().Connect().Return(true)
		setup.Remote.EXPECT().Connect().Return(false)
		assert.False(t, setup.MdcbStorage.Connect())
	})

	t.Run("delegates filter and set helpers to selected handlers", func(t *testing.T) {
		setup := setupTest(t)
		defer setup.CleanUp()

		filtered := map[string]string{"key": "value"}
		setup.Local.EXPECT().GetKeysAndValuesWithFilter("prefix").Return(filtered)
		assert.Equal(t, filtered, setup.MdcbStorage.GetKeysAndValuesWithFilter("prefix"))

		setup.Local.EXPECT().AddToSet("set-key", "value")
		setup.MdcbStorage.AddToSet("set-key", "value")

		setup.Local.EXPECT().RemoveFromSet("set-key", "value")
		setup.MdcbStorage.RemoveFromSet("set-key", "value")
	})

	t.Run("GetSet falls back to RPC after local error", func(t *testing.T) {
		setup := setupTest(t)
		defer setup.CleanUp()

		localErr := errors.New("local miss")
		rpcSet := map[string]string{"rpc": "value"}
		setup.Local.EXPECT().GetSet("set-key").Return(nil, localErr)
		setup.Remote.EXPECT().GetSet("set-key").Return(rpcSet, nil)

		got, err := setup.MdcbStorage.GetSet("set-key")
		assert.NoError(t, err)
		assert.Equal(t, rpcSet, got)
	})

	t.Run("GetListRange uses RPC when local is nil or errors", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		remote := mock.NewMockHandler(ctrl)
		remote.EXPECT().GetListRange("list-key", int64(0), int64(2)).Return([]string{"rpc"}, nil)
		mdcb := NewMdcbStorage(nil, remote, getTestLogger(), nil)

		got, err := mdcb.GetListRange("list-key", 0, 2)
		assert.NoError(t, err)
		assert.Equal(t, []string{"rpc"}, got)

		setup := setupTest(t)
		defer setup.CleanUp()
		setup.Local.EXPECT().GetListRange("list-key", int64(0), int64(2)).Return(nil, errors.New("local miss"))
		setup.Remote.EXPECT().GetListRange("list-key", int64(0), int64(2)).Return([]string{"fallback"}, nil)

		got, err = setup.MdcbStorage.GetListRange("list-key", 0, 2)
		assert.NoError(t, err)
		assert.Equal(t, []string{"fallback"}, got)
	})

	t.Run("RemoveFromList and AppendToSet combine local and RPC handlers", func(t *testing.T) {
		setup := setupTest(t)
		defer setup.CleanUp()

		setup.Local.EXPECT().RemoveFromList("list-key", "value").Return(errors.New("local failed"))
		setup.Remote.EXPECT().RemoveFromList("list-key", "value").Return(nil)
		assert.NoError(t, setup.MdcbStorage.RemoveFromList("list-key", "value"))

		setup.Local.EXPECT().AppendToSet("list-key", "value")
		setup.Remote.EXPECT().AppendToSet("list-key", "value")
		setup.MdcbStorage.AppendToSet("list-key", "value")

		setup = setupTest(t)
		defer setup.CleanUp()

		setup.Local.EXPECT().RemoveFromList("list-key", "value").Return(errors.New("local failed"))
		setup.Remote.EXPECT().RemoveFromList("list-key", "value").Return(errors.New("rpc failed"))
		assert.EqualError(t, setup.MdcbStorage.RemoveFromList("list-key", "value"), "cannot delete key in storages")
	})

	t.Run("Exists requires both handlers and maps dual errors", func(t *testing.T) {
		setup := setupTest(t)
		defer setup.CleanUp()

		setup.Local.EXPECT().Exists("key").Return(true, nil)
		setup.Remote.EXPECT().Exists("key").Return(true, nil)
		exists, err := setup.MdcbStorage.Exists("key")
		assert.NoError(t, err)
		assert.True(t, exists)

		setup = setupTest(t)
		defer setup.CleanUp()

		setup.Local.EXPECT().Exists("key").Return(false, errors.New("local failed"))
		setup.Remote.EXPECT().Exists("key").Return(false, errors.New("rpc failed"))
		exists, err = setup.MdcbStorage.Exists("key")
		assert.EqualError(t, err, "cannot find key in storages")
		assert.False(t, exists)
	})
}

// Verifies: STK-REQ-098, SYS-REQ-186, SW-REQ-173
// SW-REQ-173:nominal:nominal
// SW-REQ-173:boundary:nominal
// SW-REQ-173:error_handling:nominal
// SW-REQ-173:error_handling:negative
// SW-REQ-173:encoding_safety:nominal
// SW-REQ-173:determinism:nominal
func TestMdcbStorageUnsupportedMethodsPanic(t *testing.T) {
	mdcb := NewMdcbStorage(nil, nil, getTestLogger(), nil)

	testCases := []struct {
		name string
		run  func()
	}{
		{name: "GetRawKey", run: func() { _, _ = mdcb.GetRawKey("key") }},
		{name: "SetRawKey", run: func() { _ = mdcb.SetRawKey("key", "value", 0) }},
		{name: "SetExp", run: func() { _ = mdcb.SetExp("key", 0) }},
		{name: "GetExp", run: func() { _, _ = mdcb.GetExp("key") }},
		{name: "DeleteAllKeys", run: func() { _ = mdcb.DeleteAllKeys() }},
		{name: "DeleteRawKey", run: func() { _ = mdcb.DeleteRawKey("key") }},
		{name: "DeleteRawKeys", run: func() { _ = mdcb.DeleteRawKeys([]string{"key"}) }},
		{name: "GetKeysAndValues", run: func() { _ = mdcb.GetKeysAndValues() }},
		{name: "DeleteKeys", run: func() { _ = mdcb.DeleteKeys([]string{"key"}) }},
		{name: "Decrement", run: func() { mdcb.Decrement("key") }},
		{name: "IncrememntWithExpire", run: func() { _ = mdcb.IncrememntWithExpire("key", 0) }},
		{name: "SetRollingWindow", run: func() { _, _ = mdcb.SetRollingWindow("key", 1, "value", false) }},
		{name: "GetRollingWindow", run: func() { _, _ = mdcb.GetRollingWindow("key", 1, false) }},
		{name: "GetAndDeleteSet", run: func() { _ = mdcb.GetAndDeleteSet("key") }},
		{name: "GetKeyPrefix", run: func() { _ = mdcb.GetKeyPrefix() }},
		{name: "AddToSortedSet", run: func() { mdcb.AddToSortedSet("key", "value", 1) }},
		{name: "GetSortedSetRange", run: func() { _, _, _ = mdcb.GetSortedSetRange("key", "0", "1") }},
		{name: "RemoveSortedSetRange", run: func() { _ = mdcb.RemoveSortedSetRange("key", "0", "1") }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.PanicsWithValue(t, "implement me", tc.run)
		})
	}
}

// Verifies: STK-REQ-098, SYS-REQ-186, SW-REQ-173
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

// Verifies: STK-REQ-098, SYS-REQ-186, SW-REQ-173
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

	mdcb := NewMdcbStorage(localHandler, rpcHandler, log, nil)

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

// Verifies: STK-REQ-098, SYS-REQ-186, SW-REQ-173
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

// Verifies: STK-REQ-098, SYS-REQ-186, SW-REQ-173
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

// Verifies: STK-REQ-098, SYS-REQ-186, SW-REQ-173
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

// Verifies: STK-REQ-098, SYS-REQ-186, SW-REQ-173
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

// Verifies: STK-REQ-098, SYS-REQ-186, SW-REQ-173
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
