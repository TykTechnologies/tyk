package goplugin

import (
	"errors"
	"os"

	logger "github.com/TykTechnologies/tyk/log"
)

var log = logger.Get()

// interface so we can test which plugin should be loaded
type storage interface {
	fileExist(string) bool
}

// FileSystemStorage implements storage interface, it uses the filesystem as store
type FileSystemStorage struct{}

func (FileSystemStorage) fileExist(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist)
}
