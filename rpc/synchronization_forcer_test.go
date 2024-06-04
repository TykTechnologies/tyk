package rpc

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/storage"
)

var rc *storage.ConnectionHandler

func TestMain(m *testing.M) {
	conf, err := config.New()
	if err != nil {
		panic(err)
	}

	rc = storage.NewConnectionHandler(context.Background())
	go rc.Connect(context.Background(), nil, conf)

	timeout, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	connected := rc.WaitConnect(timeout)
	if !connected {
		panic("can't connect to redis '" + conf.Storage.Host + "', timeout")
	}

	os.Exit(m.Run())
}

func TestNewSyncForcer(t *testing.T) {
	sf := NewSyncForcer(rc, func() []byte { return []byte{} })

	assert.True(t, sf.store.ControllerInitiated())
	assert.Equal(t, "synchronizer-group-", sf.store.KeyPrefix)

	assert.Equal(t, true, sf.store.ConnectionHandler.Connected())
}

func TestGroupLoginCallback(t *testing.T) {
	sf := NewSyncForcer(rc, func() []byte { return []byte{} })
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

func TestGetNodeDataFunc(t *testing.T) {
	// Checking if the getNodeDataFunc is returning different values on each call
	valueToFetch := "foo"
	sf := NewSyncForcer(rc, func() []byte { return []byte(valueToFetch) })
	assert.Equal(t, valueToFetch, string(sf.getNodeDataFunc()))

	valueToFetch = "bar"
	assert.Equal(t, valueToFetch, string(sf.getNodeDataFunc()))
}
