package certs

import (
	"strings"

	"github.com/sirupsen/logrus"
)

// certIndex owns the per-organisation certificate index: the Redis list
// "<org>-index" of "raw-<certID>" entries maintained by Add and Delete, and the
// "<org>-index-migrated" marker set once the list has been built from
// certificates stored before the index existed.
//
// store is this gateway's own Redis: the same handler the certificates are
// stored in on a standalone or control plane gateway, the local half of the
// MDCB layer on a data plane. All reads and the migrated marker use it, so
// listing never reads the control plane's index or marker.
//
// writer receives index additions and removals. It is the handler the
// certificates are stored in, so on a data plane entries are written through
// the MDCB layer to both the local and the control plane index, as before.
type certIndex struct {
	store  StorageHandler
	writer StorageHandler
	logger *logrus.Entry
}

func (i certIndex) listKey(orgID string) string {
	return orgID + "-index"
}

func (i certIndex) markerKey(orgID string) string {
	return orgID + "-index-migrated"
}

// ids returns the organisation's indexed certificate IDs. The second value is
// false when the organisation has no index.
func (i certIndex) ids(orgID string) ([]string, bool) {
	exists, err := i.store.Exists(i.listKey(orgID))
	if err != nil {
		i.logger.WithError(err).Warn("Could not check certificate index for org ", orgID)
	}
	if !exists {
		return []string{}, false
	}

	keys, err := i.store.GetListRange(i.listKey(orgID), 0, -1)
	if err != nil {
		i.logger.WithError(err).Warn("Could not read certificate index for org ", orgID)
	}
	return uniqCertIDs(keys), true
}

func (i certIndex) add(orgID, certID string) {
	i.writer.AppendToSet(i.listKey(orgID), "raw-"+certID)
}

func (i certIndex) remove(orgID, certID string) {
	if err := i.writer.RemoveFromList(i.listKey(orgID), "raw-"+certID); err != nil {
		i.logger.WithError(err).Warn("Could not remove certificate ", MaskCertID(certID), " from index of org ", orgID)
	}
}

// scan reads certificate IDs straight from the stored certificates, for all
// organisations when orgID is empty.
func (i certIndex) scan(orgID string) []string {
	return uniqCertIDs(i.store.GetKeys("raw-" + orgID + "*"))
}

func (i certIndex) migrated(orgID string) bool {
	_, err := i.store.GetKey(i.markerKey(orgID))
	return err == nil
}

func (i certIndex) markMigrated(orgID string) {
	if err := i.store.SetKey(i.markerKey(orgID), "1", 0); err != nil {
		i.logger.WithError(err).Warn("Could not mark certificate index of org ", orgID, " as migrated")
	}
}

// uniqCertIDs turns stored "raw-<certID>" keys into certificate IDs, each returned
// once in first-seen order. The index is a Redis list and older versions
// appended the same certificate more than once.
func uniqCertIDs(keys []string) []string {
	out := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		id := strings.TrimPrefix(key, "raw-")
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}

	return out
}
