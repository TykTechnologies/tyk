package rpc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
)

var rc *storage.RedisController

func init() {
	conf, err := config.New()
	if err != nil {
		panic(err)
	}

	rc = storage.NewRedisController(context.Background())
	go rc.ConnectToRedis(context.Background(), nil, conf)

	timeout, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	connected := rc.WaitConnect(timeout)
	if !connected {
		panic("can't connect to redis '" + conf.Storage.Host + "', timeout")
	}
}

func TestNewSyncForcer(t *testing.T) {
	sf := NewSyncForcer(rc, []byte{})

	assert.True(t, sf.store.ControllerInitiated())
	assert.Equal(t, "synchronizer-group-", sf.store.KeyPrefix)

	assert.Equal(t, true, sf.store.RedisController.Connected())
}

func TestGroupLoginCallback(t *testing.T) {
	sf := NewSyncForcer(rc, []byte{})
	defer sf.store.DeleteAllKeys()

	key := "key"
	groupID := "group"

	//first time, it should force since the group key doesn't exists
	groupLogin, ok := sf.GroupLoginCallback(key, groupID).(apidef.GroupLoginRequest)
	assert.True(t, ok)
	assert.Equal(t, true, groupLogin.ForceSync)
	assert.Equal(t, key, groupLogin.UserKey)
	assert.Equal(t, groupID, groupLogin.GroupID)

	//second time, it shouldn't force since the group key already exists
	groupLogin, ok = sf.GroupLoginCallback(key, groupID).(apidef.GroupLoginRequest)
	assert.True(t, ok)
	assert.Equal(t, false, groupLogin.ForceSync)
	assert.Equal(t, key, groupLogin.UserKey)
	assert.Equal(t, groupID, groupLogin.GroupID)
}
