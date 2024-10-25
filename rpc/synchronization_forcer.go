package rpc

import (
	"errors"
	"sync"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/storage"
)

type SyncronizerForcer struct {
	store             *storage.RedisCluster
	getNodeDataFunc   func() []byte
	isFirstConnection bool
}

var (
	syncForcerInstance *SyncronizerForcer
	syncForcerOnce     sync.Once
)

// NewSyncForcer returns a new syncforcer with a connected redis with a key prefix synchronizer-group- for group synchronization control.
func NewSyncForcer(controller *storage.ConnectionHandler, getNodeDataFunc func() []byte) *SyncronizerForcer {
	syncForcerOnce.Do(func() {
		sf := &SyncronizerForcer{}
		sf.store = &storage.RedisCluster{KeyPrefix: "synchronizer-group-", ConnectionHandler: controller}
		sf.store.Connect()
		sf.getNodeDataFunc = getNodeDataFunc
		sf.isFirstConnection = true

		syncForcerInstance = sf
	})

	if syncForcerInstance != nil {
		syncForcerInstance.getNodeDataFunc = getNodeDataFunc
	}

	return syncForcerInstance
}

func (sf *SyncronizerForcer) SetFirstConnection(isFirstConnection bool) {
	sf.isFirstConnection = isFirstConnection
}

func (sf *SyncronizerForcer) GetIsFirstConnection() bool {
	return sf.isFirstConnection
}

// GroupLoginCallback checks if the groupID key exists in the storage to turn on/off ForceSync param.
// If the the key doesn't exists in the storage, it creates it and set ForceSync to true
func (sf *SyncronizerForcer) GroupLoginCallback(userKey string, groupID string) interface{} {
	shouldForce := sf.isFirstConnection
	sf.SetFirstConnection(false)

	_, err := sf.store.GetKey(groupID)
	if err != nil && errors.Is(err, storage.ErrKeyNotFound) {
		shouldForce = true

		err = sf.store.SetKey(groupID, "", 0)
		if err != nil {
			Log.Error("error setting syncforcer key", err)
		}
		Log.Info("Forcing MDCB synchronization for group:", groupID)
	}

	return apidef.GroupLoginRequest{
		UserKey:   userKey,
		GroupID:   groupID,
		Node:      sf.getNodeDataFunc(),
		ForceSync: shouldForce,
	}
}
