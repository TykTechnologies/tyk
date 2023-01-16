package goplugin

import (
	"errors"
	"os"

	logger "github.com/TykTechnologies/tyk/log"
)

var log = logger.Get()

// Storage interface so we can test which plugin should be loaded
type Storage interface {
	FileExist(string) bool
}

// FileSystemStorage implements storage interface, it uses the filesystem as store
type FileSystemStorage struct{}

func (FileSystemStorage) FileExist(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		log.Warningf("plugin file %v doesn't exist", path)
		return false
	}
	return true
}
