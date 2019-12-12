package storage

import "testing"

func TestRedisClusterGetMultiKey(t *testing.T) {
	t.Skip()

	keys := []string{"first", "second"}
	r := RedisCluster{KeyPrefix: "test-cluster"}
	for _, v := range keys {
		r.DeleteKey(v)
	}
	_, err := r.GetMultiKey(keys)
	if err != ErrKeyNotFound {
		t.Errorf("expected %v got %v", ErrKeyNotFound, err)
	}
	err = r.SetKey(keys[0], keys[0], 0)
	if err != nil {
		t.Fatal(err)
	}

	v, err := r.GetMultiKey(keys)
	if err != nil {
		t.Fatal(err)
	}
	if v[0] != keys[0] {
		t.Errorf("expected %s got %s", keys[0], v[0])
	}
}
