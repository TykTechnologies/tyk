package certs

import "errors"

type dummyStorage struct {
	data      map[string]string
	indexList map[string][]string
}

func newDummyStorage() *dummyStorage {
	return &dummyStorage{
		data:      make(map[string]string),
		indexList: make(map[string][]string),
	}
}

func (s *dummyStorage) GetMultiKey([]string) ([]string, error) {
	panic("implement me")
}

func (s *dummyStorage) GetRawKey(string) (string, error) {
	panic("implement me")
}

func (s *dummyStorage) SetRawKey(string, string, int64) error {
	panic("implement me")
}

func (s *dummyStorage) SetExp(string, int64) error {
	panic("implement me")
}

func (s *dummyStorage) GetExp(string) (int64, error) {
	panic("implement me")
}

func (s *dummyStorage) DeleteAllKeys() bool {
	panic("implement me")
}

func (s *dummyStorage) DeleteRawKey(string) bool {
	panic("implement me")
}

func (s *dummyStorage) Connect() bool {
	panic("implement me")
}

func (s *dummyStorage) GetKeysAndValues() map[string]string {
	panic("implement me")
}

func (s *dummyStorage) GetKeysAndValuesWithFilter(string) map[string]string {
	panic("implement me")
}

func (s *dummyStorage) DeleteKeys([]string) bool {
	panic("implement me")
}

func (s *dummyStorage) Decrement(string) {
	panic("implement me")
}

func (s *dummyStorage) IncrememntWithExpire(string, int64) int64 {
	panic("implement me")
}

func (s *dummyStorage) SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{}) {
	panic("implement me")
}

func (s *dummyStorage) GetRollingWindow(key string, per int64, pipeline bool) (int, []interface{}) {
	panic("implement me")
}

func (s *dummyStorage) GetSet(string) (map[string]string, error) {
	panic("implement me")
}

func (s *dummyStorage) AddToSet(string, string) {
	panic("implement me")
}

func (s *dummyStorage) GetAndDeleteSet(string) []interface{} {
	panic("implement me")
}

func (s *dummyStorage) RemoveFromSet(string, string) {
	panic("implement me")
}

func (s *dummyStorage) GetKeyPrefix() string {
	panic("implement me")
}

func (s *dummyStorage) AddToSortedSet(string, string, float64) {
	panic("implement me")
}

func (s *dummyStorage) GetSortedSetRange(string, string, string) ([]string, []float64, error) {
	panic("implement me")
}

func (s *dummyStorage) RemoveSortedSetRange(string, string, string) error {
	panic("implement me")
}

func (s *dummyStorage) GetKey(key string) (string, error) {
	if value, ok := s.data[key]; ok {
		return value, nil
	}

	return "", errors.New("Not found")
}

func (s *dummyStorage) SetKey(key, value string, exp int64) error {
	s.data[key] = value
	return nil
}

func (s *dummyStorage) DeleteKey(key string) bool {
	if _, ok := s.data[key]; !ok {
		return false
	}

	delete(s.data, key)
	return true
}

func (s *dummyStorage) DeleteScanMatch(pattern string) bool {
	if pattern == "*" {
		s.data = make(map[string]string)
		return true
	}

	return false
}

func (s *dummyStorage) RemoveFromList(keyName, value string) error {
	for key, keyList := range s.indexList {
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
			s.indexList[key] = new
		}
	}

	return nil
}

func (s *dummyStorage) GetListRange(keyName string, from, to int64) ([]string, error) {
	for key := range s.indexList {
		if key == keyName {
			return s.indexList[key], nil
		}
	}
	return []string{}, nil
}

func (s *dummyStorage) Exists(keyName string) (bool, error) {
	_, existIndex := s.indexList[keyName]
	_, existRaw := s.data[keyName]
	return existIndex || existRaw, nil
}

func (s *dummyStorage) AppendToSet(keyName string, value string) {
	s.indexList[keyName] = append(s.indexList[keyName], value)
}

func (s *dummyStorage) GetKeys(pattern string) (keys []string) {
	if pattern != "*" {
		return nil
	}

	for k := range s.data {
		keys = append(keys, k)
	}

	return keys
}
