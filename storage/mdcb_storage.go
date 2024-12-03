package storage

import (
	"errors"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	oauthClient = "Oauth Client"
	certificate = "Certificate"
	apiKey      = "ApiKey"
	Key         = "Key"
)

type MdcbStorage struct {
	local                            Handler
	rpc                              Handler
	logger                           *logrus.Entry
	CallbackonPullCertificatefromRPC *func(key string, val string) error
	CallbackOnPullOauthFromRPC       *func(key string, val string) error
}

func NewMdcbStorage(local, rpc Handler, log *logrus.Entry) *MdcbStorage {
	return &MdcbStorage{
		local:  local,
		rpc:    rpc,
		logger: log,
	}
}

func (m MdcbStorage) cacheCertificate(key, val string) {
	if m.CallbackonPullCertificatefromRPC != nil {
		err := (*m.CallbackonPullCertificatefromRPC)(key, val)
		if err != nil {
			m.logger.WithError(err).Error("cannot save locally certificate")
		}
	}
}

func (m MdcbStorage) cacheOAuthClient(key, val string) {
	m.logger.Infof("Key Prefix: %v", m.local.GetKeyPrefix())
	err := m.local.SetKey(key, val, 0)
	if err != nil {
		m.logger.WithError(err).Errorf("Cannot save locally oauth client: %v", key)
	}
}

// processResourceByType based on the type of key it will trigger the proper
// caching mechanism
func (m MdcbStorage) processResourceByType(key, val string) {
	resourceType := getResourceType(key)
	switch resourceType {
	case oauthClient:
		m.cacheOAuthClient(key, val)
	case certificate:
		m.cacheCertificate(key, val)
	}
}

// getFromRPCAndCache pulls a resource from rpc and stores it in local redis for caching
func (m MdcbStorage) getFromRPCAndCache(key string) (string, error) {
	val, err := m.rpc.GetKey(key)
	if err != nil {
		resourceType := getResourceType(key)
		m.logger.Errorf("cannot retrieve %v from rpc: %v... Key: %v", resourceType, err.Error(), key)
		return "", err
	}

	m.processResourceByType(key, val)
	return val, nil
}

func (m MdcbStorage) getFromLocal(key string) (string, error) {
	return m.local.GetKey(key)
}

func (m MdcbStorage) GetKey(key string) (string, error) {
	m.logger.Infof("Pulling key: %v", key)

	if m.local != nil {
		val, err := m.getFromLocal(key)
		if err == nil {
			return val, nil
		}
		m.logger.Debugf("Key not present locally, pulling from rpc layer: %v", err)
	}

	return m.getFromRPCAndCache(key)
}

func getResourceType(key string) string {
	switch {
	case strings.Contains(key, "oauth-clientid."):
		return oauthClient
	case strings.HasPrefix(key, "cert"):
		return certificate
	case strings.HasPrefix(key, "apikey"):
		return apiKey
	default:
		return Key
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

func (m MdcbStorage) GetKeysAndValuesWithFilter(key string) map[string]string {
	return m.local.GetKeysAndValuesWithFilter(key)
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
