package storage

import "errors"

type DummyStorage struct {
	Data      map[string]string
	IndexList map[string][]string
}

func NewDummyStorage() *DummyStorage {
	return &DummyStorage{
		Data:      make(map[string]string),
		IndexList: make(map[string][]string),
	}
}

func (s *DummyStorage) GetMultiKey([]string) ([]string, error) {
	panic("implement me")
}

func (s *DummyStorage) GetRawKey(string) (string, error) {
	panic("implement me")
}

func (s *DummyStorage) SetRawKey(string, string, int64) error {
	panic("implement me")
}

func (s *DummyStorage) SetExp(string, int64) error {
	panic("implement me")
}

func (s *DummyStorage) GetExp(string) (int64, error) {
	panic("implement me")
}

func (s *DummyStorage) DeleteAllKeys() bool {
	panic("implement me")
}

func (s *DummyStorage) DeleteRawKey(string) bool {
	panic("implement me")
}

func (s *DummyStorage) Connect() bool {
	panic("implement me")
}

func (s *DummyStorage) GetKeysAndValues() map[string]string {
	panic("implement me")
}

func (s *DummyStorage) GetKeysAndValuesWithFilter(string) map[string]string {
	panic("implement me")
}

func (s *DummyStorage) DeleteKeys([]string) bool {
	panic("implement me")
}

func (s *DummyStorage) Decrement(string) {
	panic("implement me")
}

func (s *DummyStorage) IncrememntWithExpire(string, int64) int64 {
	panic("implement me")
}

func (s *DummyStorage) SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{}) {
	panic("implement me")
}

func (s *DummyStorage) GetRollingWindow(key string, per int64, pipeline bool) (int, []interface{}) {
	panic("implement me")
}

func (s *DummyStorage) GetSet(string) (map[string]string, error) {
	panic("implement me")
}

func (s *DummyStorage) AddToSet(string, string) {
	panic("implement me")
}

func (s *DummyStorage) GetAndDeleteSet(string) []interface{} {
	panic("implement me")
}

func (s *DummyStorage) RemoveFromSet(string, string) {
	panic("implement me")
}

func (s *DummyStorage) GetKeyPrefix() string {
	panic("implement me")
}

func (s *DummyStorage) AddToSortedSet(string, string, float64) {
	panic("implement me")
}

func (s *DummyStorage) GetSortedSetRange(string, string, string) ([]string, []float64, error) {
	panic("implement me")
}

func (s *DummyStorage) RemoveSortedSetRange(string, string, string) error {
	panic("implement me")
}

func (s *DummyStorage) GetKey(key string) (string, error) {
	if value, ok := s.Data[key]; ok {
		return value, nil
	}

	return "", errors.New("Not found")
}

func (s *DummyStorage) SetKey(key, value string, exp int64) error {
	s.Data[key] = value
	return nil
}

func (s *DummyStorage) DeleteKey(key string) bool {
	if _, ok := s.Data[key]; !ok {
		return false
	}

	delete(s.Data, key)
	return true
}

func (s *DummyStorage) DeleteScanMatch(pattern string) bool {
	if pattern == "*" {
		s.Data = make(map[string]string)
		return true
	}

	return false
}

func (s *DummyStorage) RemoveFromList(keyName, value string) error {
	for key, keyList := range s.IndexList {
		if key == keyName {
			new := keyList[:]
			newL := 0
			for _, e := range new {
				if e == value {
					continue
				}

				new[newL] = e
				newL++
			}
			new = new[:newL]
			s.IndexList[key] = new
		}
	}

	return nil
}

func (s *DummyStorage) GetListRange(keyName string, from, to int64) ([]string, error) {
	for key := range s.IndexList {
		if key == keyName {
			return s.IndexList[key], nil
		}
	}
	return []string{}, nil
}

func (s *DummyStorage) Exists(keyName string) (bool, error) {
	_, existIndex := s.IndexList[keyName]
	_, existRaw := s.Data[keyName]
	return existIndex || existRaw, nil
}

func (s *DummyStorage) AppendToSet(keyName string, value string) {
	s.IndexList[keyName] = append(s.IndexList[keyName], value)
}

func (s *DummyStorage) GetKeys(pattern string) (keys []string) {
	if pattern != "*" {
		return nil
	}

	for k := range s.Data {
		keys = append(keys, k)
	}

	return keys
}
