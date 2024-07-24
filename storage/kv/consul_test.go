package kv

import (
	"github.com/stretchr/testify/assert"
	"testing"

	consulapi "github.com/hashicorp/consul/api"

	"github.com/TykTechnologies/tyk/config"
)

var _ Store = (*Consul)(nil)

func TestConsul_Get(t *testing.T) {
	t.Skip()

	store, err := NewConsul(config.Default.KV.Consul)
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.Get("key")

	assert.ErrorIsf(t, err, ErrKeyNotFound, "Expect key not to exists")

	con := store.(*Consul)

	_, err = con.store.Put(&consulapi.KVPair{
		Key:   "key",
		Value: []byte("value"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	val, err := store.Get("key")
	if err != nil {
		t.Fatal(err)
	}

	if val != "value" {
		t.Fatalf("Got an unexpected value.. Expected %s, got %s", "value", val)
	}

	// Clean up
	_, err = con.store.Delete("key", nil)
	if err != nil {
		t.Fatal(err)
	}
}
