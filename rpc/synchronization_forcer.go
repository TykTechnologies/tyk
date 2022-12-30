package rpc

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/storage"
)

type SyncronizerForcer struct {
	store *storage.RedisCluster
}

func NewSyncForcer(redisController *storage.RedisController) *SyncronizerForcer {
	sf := &SyncronizerForcer{}

	sf.store = &storage.RedisCluster{KeyPrefix: "synchronizer-group-", RedisController: redisController}
	sf.store.Connect()

	return sf
}

func (sf *SyncronizerForcer) GrouLoginCallback(userKey string, groupID string) interface{} {
	shouldForce := false

	_, err := sf.store.GetKey(groupID)
	if err != nil && err == storage.ErrKeyNotFound {
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
