package rpc

import (
	"errors"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/storage"
)

type SyncronizerForcer struct {
	store *storage.RedisCluster
}

//NewSyncForcer returns a new syncforcer with a connected redis with a key prefix synchronizer-group- for group synchronization control.
func NewSyncForcer(redisController *storage.RedisController) *SyncronizerForcer {
	sf := &SyncronizerForcer{}

	sf.store = &storage.RedisCluster{KeyPrefix: "synchronizer-group-", RedisController: redisController}
	sf.store.Connect()

	return sf
}

// GroupLoginCallback checks if the groupID key exists in the storage to turn on/off ForceSync param.
// If the the key doesn't exists in the storage, it creates it and set ForceSync to true
func (sf *SyncronizerForcer) GroupLoginCallback(userKey string, groupID string) interface{} {
	shouldForce := false

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
		ForceSync: shouldForce,
	}
}
