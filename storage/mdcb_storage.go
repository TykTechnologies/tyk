package storage

import (
	"errors"

	"github.com/sirupsen/logrus"
)

type MdcbStorage struct {
	local                 Handler
	rpc                   Handler
	logger                *logrus.Entry
	CallbackonPullfromRPC *func(key string, val string) error
}

func NewMdcbStorage(local, rpc Handler, log *logrus.Entry) *MdcbStorage {
	return &MdcbStorage{
		local:  local,
		rpc:    rpc,
		logger: log,
	}
}

func (m MdcbStorage) GetKey(key string) (string, error) {
	var val string
	var err error

	if m.local == nil {
		return m.rpc.GetKey(key)
	}

	val, err = m.local.GetKey(key)
	if err != nil {
		m.logger.Infof("Retrieving key from rpc.")
		val, err = m.rpc.GetKey(key)

		if err != nil {
			m.logger.Error("cannot retrieve key from rpc:" + err.Error())
			return val, err
		}

		if m.CallbackonPullfromRPC != nil {
			err := (*m.CallbackonPullfromRPC)(key, val)
			if err != nil {
				m.logger.Error(err)
			}
		}
	}

	return val, err
}

func (m MdcbStorage) GetMultiKey([]string) ([]string, error) {
	panic("implement me")
}

func (m MdcbStorage) GetRawKey(string) (string, error) {
	panic("implement me")
}

func (m MdcbStorage) SetKey(key string, content string, TTL int64) error {
	// only set the value locally as rpc writtes is not allowed
	errLocal := m.local.SetKey(key, content, TTL)

	if errLocal != nil {
		return errors.New("cannot save key in local")
	}

	return nil
}

func (m MdcbStorage) SetRawKey(string, string, int64) error {
	panic("implement me")
}

func (m MdcbStorage) SetExp(string, int64) error {
	panic("implement me")
}

func (m MdcbStorage) GetExp(string) (int64, error) {
	panic("implement me")
}

func (m MdcbStorage) GetKeys(key string) []string {
	var val []string

	if m.local != nil {
		val = m.local.GetKeys(key)
		if len(val) == 0 {
			val = m.rpc.GetKeys(key)
		}
	} else {
		val = m.rpc.GetKeys(key)
	}
	return val
}

func (m MdcbStorage) DeleteKey(key string) bool {
	deleteLocal := m.local.DeleteKey(key)
	deleteRPC := m.rpc.DeleteKey(key)

	return deleteLocal || deleteRPC
}

func (m MdcbStorage) DeleteAllKeys() bool {
	panic("implement me")
}

func (m MdcbStorage) DeleteRawKey(string) bool {
	panic("implement me")
}

func (m MdcbStorage) Connect() bool {
	return m.local.Connect() && m.rpc.Connect()
}

func (m MdcbStorage) GetKeysAndValues() map[string]string {
	panic("implement me")
}

func (m MdcbStorage) GetKeysAndValuesWithFilter(string) map[string]string {
	panic("implement me")
}

func (m MdcbStorage) DeleteKeys([]string) bool {
	panic("implement me")
}

func (m MdcbStorage) Decrement(string) {
	panic("implement me")
}

func (m MdcbStorage) IncrememntWithExpire(string, int64) int64 {
	panic("implement me")
}

func (m MdcbStorage) SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{}) {
	panic("implement me")
}

func (m MdcbStorage) GetRollingWindow(key string, per int64, pipeline bool) (int, []interface{}) {
	panic("implement me")
}

func (m MdcbStorage) GetSet(key string) (map[string]string, error) {
	val, err := m.local.GetSet(key)
	if err != nil {
		// try rpc
		val, err = m.rpc.GetSet(key)
	}
	return val, err
}

func (m MdcbStorage) AddToSet(key string, value string) {
	m.local.AddToSet(key, value)
}

func (m MdcbStorage) GetAndDeleteSet(string) []interface{} {
	panic("implement me")
}

func (m MdcbStorage) RemoveFromSet(key string, value string) {
	m.local.RemoveFromSet(key, value)
}

func (m MdcbStorage) DeleteScanMatch(key string) bool {
	deleteLocal := m.local.DeleteScanMatch(key)
	deleteRPC := m.rpc.DeleteScanMatch(key)

	return deleteLocal || deleteRPC
}

func (m MdcbStorage) GetKeyPrefix() string {
	panic("implement me")
}

func (m MdcbStorage) AddToSortedSet(string, string, float64) {
	panic("implement me")
}

func (m MdcbStorage) GetSortedSetRange(string, string, string) ([]string, []float64, error) {
	panic("implement me")
}

func (m MdcbStorage) RemoveSortedSetRange(string, string, string) error {
	panic("implement me")
}

func (m MdcbStorage) GetListRange(key string, from int64, to int64) ([]string, error) {
	var val []string
	var err error

	if m.local == nil {
		return m.rpc.GetListRange(key, from, to)
	}

	val, err = m.local.GetListRange(key, from, to)
	if err != nil {
		val, err = m.rpc.GetListRange(key, from, to)
	}

	return val, err
}

func (m MdcbStorage) RemoveFromList(key string, value string) error {
	errLocal := m.local.RemoveFromList(key, value)
	errRpc := m.rpc.RemoveFromList(key, value)

	if errLocal != nil && errRpc != nil {
		return errors.New("cannot delete key in storages")
	}

	return nil
}

func (m MdcbStorage) AppendToSet(key string, value string) {
	m.local.AppendToSet(key, value)
	m.rpc.AppendToSet(key, value)
}

func (m MdcbStorage) Exists(key string) (bool, error) {
	foundLocal, errLocal := m.local.Exists(key)
	foundRpc, errRpc := m.rpc.Exists(key)

	if errLocal != nil && errRpc != nil {
		return false, errors.New("cannot find key in storages")
	}

	return foundLocal && foundRpc, nil
}
