package storage

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

// assertPanic checks if the provided function f panics. It fails the test if no panic occurs.
func assertPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	f() // Call the provided function, expecting a panic
}

func TestDummyStorage_GetMultiKey(t *testing.T) {
	ds := NewDummyStorage()
	ds.Data["key1"] = "value1"
	ds.Data["key2"] = "value2"

	tests := []struct {
		name    string
		keys    []string
		want    []string
		wantErr bool
	}{
		{
			name:    "Valid keys",
			keys:    []string{"key1", "key2"},
			want:    []string{"value1", "value2"},
			wantErr: false,
		},
		{
			name:    "Invalid key",
			keys:    []string{"unknown"},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ds.GetMultiKey(context.Background(), tt.keys)
			if (err != nil) != tt.wantErr {
				t.Errorf("DummyStorage.GetMultiKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DummyStorage.GetMultiKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDummyStorage_GetRawKey(t *testing.T) {
	ds := NewDummyStorage()
	ds.Data["key1"] = "value1"

	tests := []struct {
		name    string
		key     string
		want    string
		wantErr bool
	}{
		{
			name:    "Key exists",
			key:     "key1",
			want:    "value1",
			wantErr: false,
		},
		{
			name:    "Key does not exist",
			key:     "key2",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ds.GetRawKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("DummyStorage.GetRawKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DummyStorage.GetRawKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDummyStorage_SetRawKey(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		err := ds.SetRawKey("key", "val", 0)
		if err != nil {
			return
		}
	})
}

func TestDummyStorage_SetExp(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		err := ds.SetExp("key", 0)
		if err != nil {
			return
		}
	})
}

func TestDummyStorage_GetExp(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		_, err := ds.GetExp("key")
		if err != nil {
			return
		}
	})
}

func TestDummyStorage_DeleteAllKeys(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		ds.DeleteAllKeys()
	})
}

func TestDummyStorage_DeleteRawKey(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		ds.DeleteRawKey("key")
	})
}

func TestDummyStorage_Connect(t *testing.T) {
	ds := NewDummyStorage()
	assert.True(t, ds.Connect())
}

func TestDummyStorage_GetKeysAndValues(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		ds.GetKeysAndValues()
	})
}

func TestDummyStorage_GetKeysAndValuesWithFilter(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		ds.GetKeysAndValuesWithFilter("*")
	})
}

func TestDummyStorage_DeleteKeys(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		ds.DeleteKeys([]string{"key"})
	})
}

func TestDummyStorage_Decrement(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		ds.Decrement("key")
	})
}

func TestDummyStorage_IncrememntWithExpire(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		ds.IncrememntWithExpire("key", 0)
	})
}

func TestDummyStorage_SetRollingWindow(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		ds.SetRollingWindow("key", 1, "val", false)
	})
}

func TestDummyStorage_GetRollingWindow(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		ds.GetRollingWindow("key", 1, false)
	})
}

func TestDummyStorage_GetSet(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		_, err := ds.GetSet("Set")
		if err != nil {
			return
		}
	})
}

func TestDummyStorage_AddToSet(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		ds.AddToSet("Set", "key")
	})
}

func TestDummyStorage_GetAndDeleteSet(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		ds.GetAndDeleteSet("Set")
	})
}

func TestDummyStorage_RemoveFromSet(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		ds.RemoveFromSet("set", "key")
	})
}

func TestDummyStorage_GetKeyPrefix(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		ds.GetKeyPrefix()
	})
}

func TestDummyStorage_AddToSortedSet(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		ds.AddToSortedSet("Set", "key", 1)
	})
}

func TestDummyStorage_GetSortedSetRange(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		_, _, err := ds.GetSortedSetRange("set", "from", "to")
		if err != nil {
			return
		}
	})
}

func TestDummyStorage_RemoveSortedSetRange(t *testing.T) {
	ds := NewDummyStorage()
	assertPanic(t, func() {
		err := ds.RemoveSortedSetRange("set", "from", "to")
		if err != nil {
			return
		}
	})
}

func TestDummyStorage_GetKey(t *testing.T) {
	ds := NewDummyStorage()
	ds.Data["existingKey"] = "value1"

	tests := []struct {
		name    string
		key     string
		want    string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Key exists",
			key:     "existingKey",
			want:    "value1",
			wantErr: false,
			errMsg:  "",
		},
		{
			name:    "Key does not exist",
			key:     "nonExistingKey",
			want:    "",
			wantErr: true,
			errMsg:  "Not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ds.GetKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("DummyStorage.GetKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DummyStorage.GetKey() = %v, want %v", got, tt.want)
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("DummyStorage.GetKey() error = %v, wantErrMsg %v", err, tt.errMsg)
			}
		})
	}
}

func TestDummyStorage_SetKey(t *testing.T) {
	ds := NewDummyStorage()

	tests := []struct {
		name  string
		key   string
		value string
		exp   int64
	}{
		{
			name:  "Set key-value pair",
			key:   "testKey",
			value: "testValue",
			exp:   0, // Since expiration is not implemented, it can be set to a default value like 0
		},
		// Add more test cases if necessary
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ds.SetKey(tt.key, tt.value, tt.exp)
			if err != nil {
				t.Errorf("DummyStorage.SetKey() error = %v", err)
			}

			// Verify that the key-value pair is set correctly
			if got, exists := ds.Data[tt.key]; !exists || got != tt.value {
				t.Errorf("DummyStorage.SetKey() did not set the value correctly, got = %v, want = %v", got, tt.value)
			}
		})
	}
}

func TestDummyStorage_DeleteKey(t *testing.T) {
	ds := NewDummyStorage()
	ds.Data["key1"] = "value1"

	tests := []struct {
		name      string
		key       string
		want      bool
		expectKey bool
	}{
		{
			name:      "Delete existing key",
			key:       "key1",
			want:      true,
			expectKey: false, // After deletion, the key should not exist
		},
		{
			name:      "Delete non-existing key",
			key:       "nonExistingKey",
			want:      false,
			expectKey: false, // The key does not exist in the first place
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ds.DeleteKey(tt.key)
			if got != tt.want {
				t.Errorf("DummyStorage.DeleteKey() = %v, want %v", got, tt.want)
			}

			// Check if the key still exists in the map
			_, exists := ds.Data[tt.key]
			if exists != tt.expectKey {
				t.Errorf("After DummyStorage.DeleteKey(), key existence = %v, expectKey %v", exists, tt.expectKey)
			}
		})
	}
}

func TestDummyStorage_DeleteScanMatch(t *testing.T) {
	ds := NewDummyStorage()
	ds.Data["key1"] = "value1"
	ds.Data["key2"] = "value2"

	tests := []struct {
		name            string
		pattern         string
		want            bool
		expectDataEmpty bool
	}{
		{
			name:            "Delete all with '*' pattern",
			pattern:         "*",
			want:            true,
			expectDataEmpty: true, // Expect data to be empty after deletion
		},
		{
			name:            "Delete with non-matching pattern",
			pattern:         "nonMatchingPattern",
			want:            false,
			expectDataEmpty: true, // Data should remain unchanged
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ds.DeleteScanMatch(tt.pattern)
			if got != tt.want {
				t.Errorf("DummyStorage.DeleteScanMatch() = %v, want %v", got, tt.want)
			}

			// Check if the data map is empty or not based on the test expectation
			if (len(ds.Data) == 0) != tt.expectDataEmpty {
				t.Errorf("After DummyStorage.DeleteScanMatch(), data empty = %v, expectDataEmpty %v", len(ds.Data) == 0, tt.expectDataEmpty)
			}
		})
	}
}

func TestDummyStorage_RemoveFromList(t *testing.T) {
	ds := NewDummyStorage()

	tests := []struct {
		name     string
		keyName  string
		value    string
		wantList []string
		wantErr  bool
	}{
		{
			name:     "Remove existing value",
			keyName:  "key1",
			value:    "value2",
			wantList: []string{"value1", "value3"},
			wantErr:  false,
		},
		{
			name:     "Remove non-existing value",
			keyName:  "key1",
			value:    "nonExistingValue",
			wantList: []string{"value1", "value2", "value3"}, // List remains unchanged
			wantErr:  false,
		},
		{
			name:     "Remove from non-existing key",
			keyName:  "nonExistingKey",
			value:    "value1",
			wantList: nil, // Key does not exist
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds.IndexList["key1"] = []string{"value1", "value2", "value3"}

			err := ds.RemoveFromList(tt.keyName, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("DummyStorage.RemoveFromList() error = %v, wantErr %v", err, tt.wantErr)
			}

			gotList := ds.IndexList[tt.keyName]
			if !reflect.DeepEqual(gotList, tt.wantList) {
				t.Errorf("DummyStorage.RemoveFromList() gotList = %v, want %v", gotList, tt.wantList)
			}
		})
	}
}

func TestDummyStorage_GetListRange(t *testing.T) {
	ds := NewDummyStorage()
	ds.IndexList["key1"] = []string{"value1", "value2", "value3"}

	tests := []struct {
		name    string
		keyName string
		from    int64
		to      int64
		want    []string
		wantErr bool
	}{
		{
			name:    "Existing key",
			keyName: "key1",
			from:    0,
			to:      2,
			want:    []string{"value1", "value2", "value3"}, // Expect full list (current implementation)
			wantErr: false,
		},
		{
			name:    "Non-existing key",
			keyName: "nonExistingKey",
			from:    0,
			to:      2,
			want:    []string{}, // Expect empty list
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ds.GetListRange(tt.keyName, tt.from, tt.to)
			if (err != nil) != tt.wantErr {
				t.Errorf("DummyStorage.GetListRange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DummyStorage.GetListRange() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDummyStorage_Exists(t *testing.T) {
	ds := NewDummyStorage()
	ds.Data["dataKey"] = "value1"
	ds.IndexList["indexKey"] = []string{"value1", "value2"}

	tests := []struct {
		name    string
		keyName string
		want    bool
		wantErr bool
	}{
		{
			name:    "Key exists in Data",
			keyName: "dataKey",
			want:    true,
			wantErr: false,
		},
		{
			name:    "Key exists in IndexList",
			keyName: "indexKey",
			want:    true,
			wantErr: false,
		},
		{
			name:    "Key exists in both Data and IndexList",
			keyName: "sharedKey",
			want:    true,
			wantErr: false,
		},
		{
			name:    "Key does not exist",
			keyName: "nonExistingKey",
			want:    false,
			wantErr: false,
		},
	}

	// Add a key that exists in both Data and IndexList
	ds.Data["sharedKey"] = "sharedValue"
	ds.IndexList["sharedKey"] = []string{"sharedValue1", "sharedValue2"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ds.Exists(tt.keyName)
			if (err != nil) != tt.wantErr {
				t.Errorf("DummyStorage.Exists() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DummyStorage.Exists() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDummyStorage_AppendToSet(t *testing.T) {
	ds := NewDummyStorage()
	ds.IndexList["existingKey"] = []string{"value1", "value2"}

	tests := []struct {
		name    string
		keyName string
		value   string
		want    []string
	}{
		{
			name:    "Append to existing key",
			keyName: "existingKey",
			value:   "value3",
			want:    []string{"value1", "value2", "value3"},
		},
		{
			name:    "Append to new key",
			keyName: "newKey",
			value:   "newValue",
			want:    []string{"newValue"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds.AppendToSet(tt.keyName, tt.value)

			got := ds.IndexList[tt.keyName]
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DummyStorage.AppendToSet() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDummyStorage_GetKeys(t *testing.T) {
	ds := NewDummyStorage()
	ds.Data["key1"] = "value1"
	ds.Data["key2"] = "value2"
	ds.Data["key3"] = "value3"

	tests := []struct {
		name    string
		pattern string
		want    []string
	}{
		{
			name:    "Valid pattern '*'",
			pattern: "*",
			want:    []string{"key1", "key2", "key3"},
		},
		{
			name:    "Invalid pattern",
			pattern: "non-*",
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ds.GetKeys(tt.pattern)

			// Sort slices for consistent comparison
			sort.Strings(got)
			sort.Strings(tt.want)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DummyStorage.GetKeys() got = %v, want %v", got, tt.want)
			}
		})
	}
}
