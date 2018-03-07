package main

import (
	"errors"
	"strings"

	ldap "github.com/mavricknz/ldap"
)

// LDAPStorageHandler implements storage.Handler, this is a read-only implementation to access keys from an LDAP service
type LDAPStorageHandler struct {
	LDAPServer           string
	LDAPPort             uint16
	BaseDN               string
	Attributes           []string
	SessionAttributeName string
	SearchString         string
	store                *ldap.LDAPConnection
}

func (l *LDAPStorageHandler) LoadConfFromMeta(meta map[string]interface{}) {
	l.LDAPServer = meta["ldap_server"].(string)
	l.LDAPPort = uint16(meta["ldap_port"].(float64))
	l.BaseDN = meta["base_dn"].(string)

	attrArray := []string{}

	for _, attr := range meta["attributes"].([]interface{}) {
		val := attr.(string)
		attrArray = append(attrArray, val)
	}

	l.Attributes = attrArray
	l.SessionAttributeName = meta["session_attribute_name"].(string)
	l.SearchString = meta["search_string"].(string)

}

func (l *LDAPStorageHandler) Connect() bool {
	conn := ldap.NewLDAPConnection(l.LDAPServer, l.LDAPPort)
	if err := conn.Connect(); err != nil {
		log.Error("LDAP server connection failed: ", err)
		return false
	}
	log.Info("LDAP: Connection established")
	l.store = conn
	return true
}

func (l *LDAPStorageHandler) GetKey(filter string) (string, error) {
	log.Debug("Searching for filter: ", filter)

	useFilter := strings.Replace(l.SearchString, "TYKKEYID", filter, 1)
	log.Warning("Search filter is: ", useFilter)

	search_request := ldap.NewSearchRequest(
		l.BaseDN,
		ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
		useFilter,
		l.Attributes,
		nil)

	sr, err := l.store.Search(search_request)
	if err != nil {
		log.Debug("LDAP Key search failed: ", err)
		return "", err
	}

	if len(sr.Entries) == 0 {
		return "", nil
	}

	log.Debug("Found Key: ", sr.Entries[0])

	entry := sr.Entries[0]

	if entry.Attributes == nil {
		log.Error("LDAP: No attributes found to check for session state. Failing")
		return "", errors.New("Attributes for entry are empty")
	}

	for _, attr := range entry.Attributes {
		if attr.Name == l.SessionAttributeName {
			log.Debug("Found session data: ", attr.Values[0])
			return attr.Values[0], nil
		}
	}

	return "", nil
}

func (l *LDAPStorageHandler) GetRawKey(filter string) (string, error) {
	log.Warning("Not implementated")

	return "", nil
}

func (l *LDAPStorageHandler) SetExp(cn string, exp int64) error {
	log.Warning("Not implementated")
	return nil
}

func (l *LDAPStorageHandler) GetExp(cn string) (int64, error) {
	log.Warning("Not implementated")
	return 0, nil
}

func (l *LDAPStorageHandler) GetKeys(filter string) []string {
	log.Warning("Not implementated")
	s := []string{}

	return s
}
func (l *LDAPStorageHandler) GetKeysAndValues() map[string]string {
	log.Warning("Not implementated")

	s := map[string]string{}
	return s
}
func (l *LDAPStorageHandler) GetKeysAndValuesWithFilter(filter string) map[string]string {
	log.Warning("Not implementated")
	s := map[string]string{}
	return s
}

func (l *LDAPStorageHandler) SetKey(cn, session string, timeout int64) error {
	l.notifyReadOnly()
	return nil
}

func (l *LDAPStorageHandler) SetRawKey(cn, session string, timeout int64) error {
	l.notifyReadOnly()
	return nil
}

func (l *LDAPStorageHandler) DeleteKey(cn string) bool {
	return l.notifyReadOnly()
}

func (l *LDAPStorageHandler) DeleteRawKey(cn string) bool {
	return l.notifyReadOnly()
}

func (l *LDAPStorageHandler) DeleteKeys(keys []string) bool {
	return l.notifyReadOnly()
}

func (l *LDAPStorageHandler) Decrement(keyName string) {
	l.notifyReadOnly()
}

func (l *LDAPStorageHandler) IncrememntWithExpire(keyName string, timeout int64) int64 {
	l.notifyReadOnly()
	return 999
}

func (l *LDAPStorageHandler) notifyReadOnly() bool {
	log.Warning("LDAP storage is READ ONLY")
	return false
}

func (l *LDAPStorageHandler) SetRollingWindow(keyName string, per int64, val string, pipeline bool) (int, []interface{}) {
	log.Warning("Not Implemented!")
	return 0, nil
}

func (l LDAPStorageHandler) GetSet(keyName string) (map[string]string, error) {
	log.Error("Not implemented")
	return nil, nil
}

func (l LDAPStorageHandler) AddToSet(keyName, value string) {
	log.Error("Not implemented")
}

func (l LDAPStorageHandler) AppendToSet(keyName, value string) {
	log.Error("Not implemented")
}

func (l LDAPStorageHandler) RemoveFromSet(keyName, value string) {
	log.Error("Not implemented")
}

func (l LDAPStorageHandler) GetAndDeleteSet(keyName string) []interface{} {
	log.Error("Not implemented")
	return nil
}

func (l LDAPStorageHandler) DeleteScanMatch(pattern string) bool {
	log.Error("Not implemented")
	return false
}

func (l LDAPStorageHandler) GetKeyPrefix() string {
	log.Error("Not implemented")
	return ""
}

func (l LDAPStorageHandler) AddToSortedSet(keyName, value string, score float64) {
	log.Error("Not implemented")
}

func (l LDAPStorageHandler) GetSortedSetRange(keyName, scoreFrom, scoreTo string) ([]string, []float64, error) {
	log.Error("Not implemented")
	return nil, nil, nil
}

func (l LDAPStorageHandler) RemoveSortedSetRange(keyName, scoreFrom, scoreTo string) error {
	log.Error("Not implemented")
	return nil
}
