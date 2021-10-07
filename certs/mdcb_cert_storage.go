package certs

import (
	"errors"
	"github.com/sirupsen/logrus"
)

type mdcbCertStorage struct {
	local StorageHandler
	rpc StorageHandler
	logger          *logrus.Entry
}

func newMdcbCertStorage(local, rpc StorageHandler, log *logrus.Entry) *mdcbCertStorage{
	return &mdcbCertStorage{
		local: local,
		rpc:   rpc,
		logger:log,
	}
}

func (m *mdcbCertStorage) GetKey(key string) (string, error){
	var val string
	var err error
	if m.local != nil {
		val, err = m.local.GetKey(key)
		if err != nil {
			val, err = m.rpc.GetKey(key)
			m.logger.Info("Looking up in rpc")
		}else{
			m.logger.Info("looking up in local")
		}
	}else{
		val, err = m.rpc.GetKey(key)
	}
	return val, err
}

func (m *mdcbCertStorage) SetKey(key string, content string, TTL int64) error {
	errLocal := m.local.SetKey(key,content,TTL)
	errRpc := m.rpc.SetKey(key,content,TTL)

	m.logger.Infof("Err Local: %+v", errLocal)
	m.logger.Infof("err RPC: %+v", errRpc)
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
	}else{
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
	}else{
		val, err = m.rpc.GetListRange(keyName, from, to)
	}
	return val, err
}

func (m *mdcbCertStorage) RemoveFromList(keyName string, value string) error {
	errLocal := m.local.RemoveFromList(keyName,value)
	errRpc := m.rpc.RemoveFromList(keyName,value)

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
/*	var val bool
	var err error
	if m.local != nil {
		val, err = m.local.Exists(keyName)
		if err != nil {
			val, err = m.rpc.Exists(keyName)
		}
	}else{
		val, err = m.rpc.Exists(keyName)
	}
	return val, err*/

	foundLocal, errLocal := m.local.Exists(keyName)
	foundRpc, errRpc := m.rpc.Exists(keyName)

	if errLocal != nil && errRpc != nil {
		return false, errors.New("cannot find cert in storages")
	}

	return foundLocal && foundRpc, nil
}
