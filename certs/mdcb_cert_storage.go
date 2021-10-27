package certs

import (
	"errors"
	"strings"

	"github.com/sirupsen/logrus"
)

type mdcbCertStorage struct {
	local   StorageHandler
	rpc     StorageHandler
	logger  *logrus.Entry
	addCert func([]byte, string) (string, error)
}

func newMdcbCertStorage(local, rpc StorageHandler, log *logrus.Entry, addCert func([]byte, string) (string, error)) *mdcbCertStorage {
	return &mdcbCertStorage{
		local:   local,
		rpc:     rpc,
		logger:  log,
		addCert: addCert,
	}
}

func (m *mdcbCertStorage) GetKey(key string) (string, error) {
	var val string
	var err error

	if m.local == nil {
		return m.rpc.GetKey(key)
	}

	val, err = m.local.GetKey(key)
	if err != nil {
		m.logger.Infof("Retrieving certificate from rpc.")
		val, err = m.rpc.GetKey(key)

		if err != nil {
			m.logger.Error("cannot retrieve cert from rpc:" + err.Error())
			return val, err
		}
		// calculate the orgId from the keyId
		certID, _, _ := GetCertIDAndChainPEM([]byte(val), "")
		orgId := strings.ReplaceAll(key, "raw-", "")
		orgId = strings.ReplaceAll(orgId, certID, "")
		// save the cert in local redis
		m.addCert([]byte(val), orgId)
	}

	return val, err
}

func (m *mdcbCertStorage) SetKey(key string, content string, TTL int64) error {
	errLocal := m.local.SetKey(key, content, TTL)
	errRpc := m.rpc.SetKey(key, content, TTL)

	if errLocal != nil && errRpc != nil {
		return errors.New("cannot save cert in storages")
	}

	return nil
}

func (m *mdcbCertStorage) GetKeys(key string) []string {
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

func (m *mdcbCertStorage) DeleteKey(key string) bool {
	deleteLocal := m.local.DeleteKey(key)
	deleteRPC := m.rpc.DeleteKey(key)

	return deleteLocal || deleteRPC
}

func (m *mdcbCertStorage) DeleteScanMatch(key string) bool {
	deleteLocal := m.local.DeleteScanMatch(key)
	deleteRPC := m.rpc.DeleteScanMatch(key)

	return deleteLocal || deleteRPC
}

func (m *mdcbCertStorage) GetListRange(keyName string, from int64, to int64) ([]string, error) {
	var val []string
	var err error
	if m.local != nil {
		val, err = m.local.GetListRange(keyName, from, to)
		if err != nil {
			val, err = m.rpc.GetListRange(keyName, from, to)
		}
	} else {
		val, err = m.rpc.GetListRange(keyName, from, to)
	}
	return val, err
}

func (m *mdcbCertStorage) RemoveFromList(keyName string, value string) error {
	errLocal := m.local.RemoveFromList(keyName, value)
	errRpc := m.rpc.RemoveFromList(keyName, value)

	if errLocal != nil && errRpc != nil {
		return errors.New("cannot delete cert in storages")
	}

	return nil
}

func (m *mdcbCertStorage) AppendToSet(keyName string, value string) {
	m.local.AppendToSet(keyName, value)
	m.rpc.AppendToSet(keyName, value)
}

func (m *mdcbCertStorage) Exists(keyName string) (bool, error) {

	foundLocal, errLocal := m.local.Exists(keyName)
	foundRpc, errRpc := m.rpc.Exists(keyName)

	if errLocal != nil && errRpc != nil {
		return false, errors.New("cannot find cert in storages")
	}

	return foundLocal && foundRpc, nil
}
