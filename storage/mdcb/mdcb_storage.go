package mdcb

import (
	"errors"
	"strings"

	"github.com/TykTechnologies/tyk/interfaces"
	"github.com/sirupsen/logrus"
)

type MdcbStorage struct {
	Local                 interfaces.Handler
	Rpc                   interfaces.Handler
	Logger                *logrus.Entry
	CallbackonPullfromRPC *func(key string, val string) error
}

func NewMdcbStorage(local, rpc interfaces.Handler, log *logrus.Entry) *MdcbStorage {
	return &MdcbStorage{
		Local:  local,
		Rpc:    rpc,
		Logger: log,
	}
}

func (m MdcbStorage) GetKey(key string) (string, error) {
	var val string
	var err error

	if m.Local == nil {
		return m.Rpc.GetKey(key)
	}

	val, err = m.Local.GetKey(key)
	if err != nil {
		m.Logger.Infof("Retrieving key from rpc.")
		val, err = m.Rpc.GetKey(key)

		if err != nil {
			resourceType := getResourceType(key)
			m.Logger.Errorf("cannot retrieve %v from rpc: %v", resourceType, err.Error())
			return val, err
		}

		if m.CallbackonPullfromRPC != nil {
			err := (*m.CallbackonPullfromRPC)(key, val)
			if err != nil {
				m.Logger.Error(err)
			}
		}
	}

	return val, err
}

func getResourceType(key string) string {
	switch {
	case strings.Contains(key, "oauth-clientid."):
		return "Oauth Client"
	case strings.HasPrefix(key, "cert"):
		return "certificate"
	case strings.HasPrefix(key, "apikey"):
		return "api key"
	default:
		return "key"
	}
}

// GetMultiKey gets multiple keys from the MDCB layer
func (m MdcbStorage) GetMultiKey(keyNames []string) ([]string, error) {
	var err error
	var value string

	for _, key := range keyNames {
		value, err = m.GetKey(key)
		if err == nil {
			return []string{value}, nil
		}
	}

	return nil, err
}

func (m MdcbStorage) GetRawKey(string) (string, error) {
	panic("implement me")
}

func (m MdcbStorage) SetKey(key string, content string, TTL int64) error {
	// only set the value locally as rpc writtes is not allowed
	errLocal := m.Local.SetKey(key, content, TTL)

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

	if m.Local != nil {
		val = m.Local.GetKeys(key)
		if len(val) == 0 {
			val = m.Rpc.GetKeys(key)
		}
	} else {
		val = m.Rpc.GetKeys(key)
	}
	return val
}

func (m MdcbStorage) DeleteKey(key string) bool {
	deleteLocal := m.Local.DeleteKey(key)
	deleteRPC := m.Rpc.DeleteKey(key)

	return deleteLocal || deleteRPC
}

func (m MdcbStorage) DeleteAllKeys() bool {
	panic("implement me")
}

func (m MdcbStorage) DeleteRawKey(string) bool {
	panic("implement me")
}

func (m MdcbStorage) Connect() bool {
	return m.Local.Connect() && m.Rpc.Connect()
}

func (m MdcbStorage) GetKeysAndValues() map[string]string {
	panic("implement me")
}

func (m MdcbStorage) GetKeysAndValuesWithFilter(key string) map[string]string {
	return m.Local.GetKeysAndValuesWithFilter(key)
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
	val, err := m.Local.GetSet(key)
	if err != nil {
		// try rpc
		val, err = m.Rpc.GetSet(key)
	}
	return val, err
}

func (m MdcbStorage) AddToSet(key string, value string) {
	m.Local.AddToSet(key, value)
}

func (m MdcbStorage) GetAndDeleteSet(string) []interface{} {
	panic("implement me")
}

func (m MdcbStorage) RemoveFromSet(key string, value string) {
	m.Local.RemoveFromSet(key, value)
}

func (m MdcbStorage) DeleteScanMatch(key string) bool {
	deleteLocal := m.Local.DeleteScanMatch(key)
	deleteRPC := m.Rpc.DeleteScanMatch(key)

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

	if m.Local == nil {
		return m.Rpc.GetListRange(key, from, to)
	}

	val, err = m.Local.GetListRange(key, from, to)
	if err != nil {
		val, err = m.Rpc.GetListRange(key, from, to)
	}

	return val, err
}

func (m MdcbStorage) RemoveFromList(key string, value string) error {
	errLocal := m.Local.RemoveFromList(key, value)
	errRpc := m.Rpc.RemoveFromList(key, value)

	if errLocal != nil && errRpc != nil {
		return errors.New("cannot delete key in storages")
	}

	return nil
}

func (m MdcbStorage) AppendToSet(key string, value string) {
	m.Local.AppendToSet(key, value)
	m.Rpc.AppendToSet(key, value)
}

func (m MdcbStorage) Exists(key string) (bool, error) {
	foundLocal, errLocal := m.Local.Exists(key)
	foundRpc, errRpc := m.Rpc.Exists(key)

	if errLocal != nil && errRpc != nil {
		return false, errors.New("cannot find key in storages")
	}

	return foundLocal && foundRpc, nil
}
