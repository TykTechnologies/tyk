package goplugin

import (
	"errors"
	"os"

	logger "github.com/TykTechnologies/tyk/log"
)

var log = logger.Get()

func init() {
	pluginStorage = FileSystemStorage{}
}

// interface so we can test which plugin should be loaded
type storage interface {
	fileExist(string) bool
}

// FileSystemStorage implements storage interface, it uses the filesystem as store
type FileSystemStorage struct{}

func (FileSystemStorage) fileExist(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		log.Warningf("plugin file %v doesn't exist", path)
		return false
	}
	return true
}
