package kv

import (
	"testing"

	"github.com/TykTechnologies/tyk/v3/config"
	"github.com/hashicorp/consul/api"
)

var _ Store = (*Consul)(nil)

func TestConsul_Get(t *testing.T) {

	store, err := NewConsul(config.Global().KV.Consul)
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.Get("key")

	if err != ErrKeyNotFound {
		t.Fatal("Expect key not to exists")
	}

	con := store.(*Consul)

	_, err = con.store.Put(&api.KVPair{
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
