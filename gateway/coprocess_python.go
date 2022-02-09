// +build cgo

package gateway

import (
	"C"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/sirupsen/logrus"

	"fmt"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/coprocess"

	python "github.com/TykTechnologies/tyk/dlpython"
	"github.com/golang/protobuf/proto"
)
import (
	"os"
	"sync"
)

var (
	dispatcherClass    unsafe.Pointer
	dispatcherInstance unsafe.Pointer
	pythonLock         = sync.Mutex{}
)

// PythonDispatcher implements a coprocess.Dispatcher
type PythonDispatcher struct {
	coprocess.Dispatcher
}

// Dispatch takes a CoProcessMessage and sends it to the CP.
func (d *PythonDispatcher) Dispatch(object *coprocess.Object) (*coprocess.Object, error) {
	// Prepare the PB object:
	objectMsg, err := proto.Marshal(object)
	if err != nil {
		return nil, err
	}

	pythonLock.Lock()
	// Find the dispatch_hook:
	dispatchHookFunc, err := python.PyObjectGetAttr(dispatcherInstance, "dispatch_hook")
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Fatal(err)
		python.PyErr_Print()
		pythonLock.Unlock()
		return nil, err
	}

	objectBytes, err := python.PyBytesFromString(objectMsg)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Fatal(err)
		python.PyErr_Print()
		pythonLock.Unlock()
		return nil, err
	}

	args, err := python.PyTupleNew(1)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Fatal(err)
		python.PyErr_Print()
		pythonLock.Unlock()
		return nil, err
	}

	python.PyTupleSetItem(args, 0, objectBytes)
	result, err := python.PyObjectCallObject(dispatchHookFunc, args)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Error(err)
		python.PyErr_Print()
		pythonLock.Unlock()
		return nil, err
	}
	python.PyDecRef(args)
	python.PyDecRef(dispatchHookFunc)

	newObjectPtr, err := python.PyTupleGetItem(result, 0)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Error(err)
		python.PyErr_Print()
		pythonLock.Unlock()
		return nil, err
	}

	newObjectLen, err := python.PyTupleGetItem(result, 1)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Error(err)
		python.PyErr_Print()
		pythonLock.Unlock()
		return nil, err
	}

	newObjectBytes, err := python.PyBytesAsString(newObjectPtr, python.PyLongAsLong(newObjectLen))
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Error(err)
		python.PyErr_Print()
		pythonLock.Unlock()
		return nil, err
	}
	python.PyDecRef(result)
	pythonLock.Unlock()

	newObject := &coprocess.Object{}
	err = proto.Unmarshal(newObjectBytes, newObject)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Error(err)
		return nil, err
	}
	return newObject, nil

}

// DispatchEvent dispatches a Tyk event.
func (d *PythonDispatcher) DispatchEvent(eventJSON []byte) {
	/*
		CEventJSON := C.CString(string(eventJSON))
		defer C.free(unsafe.Pointer(CEventJSON))
		C.Python_DispatchEvent(CEventJSON)
	*/
}

// Reload triggers a reload affecting CP middlewares and event handlers.
func (d *PythonDispatcher) Reload() {
	// C.Python_ReloadDispatcher()
}

// HandleMiddlewareCache isn't used by Python.
func (d *PythonDispatcher) HandleMiddlewareCache(b *apidef.BundleManifest, basePath string) {
	pythonLock.Lock()
	defer pythonLock.Unlock()
	dispatcherLoadBundle, err := python.PyObjectGetAttr(dispatcherInstance, "load_bundle")
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Error(err)
		return
	}

	args, err := python.PyTupleNew(1)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Error(err)
		python.PyErr_Print()
		return
	}
	python.PyTupleSetItem(args, 0, basePath)
	_, err = python.PyObjectCallObject(dispatcherLoadBundle, args)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Error(err)
		python.PyErr_Print()
	}
}

// PythonInit initializes the Python interpreter.
func PythonInit(pythonVersion string) error {
	ver, err := python.FindPythonConfig(pythonVersion)
	if err != nil {
		log.WithError(err).Errorf("Python version '%s' doesn't exist", ver)
		return fmt.Errorf("python version '%s' doesn't exist", ver)
	}
	err = python.Init()
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Fatalf("Couldn't initialize Python - %s", err.Error())
		return err
	}
	log.WithFields(logrus.Fields{
		"prefix": "coprocess",
	}).Infof("Python version '%s' loaded", ver)
	return nil
}

// PythonLoadDispatcher creates reference to the dispatcher class.
func PythonLoadDispatcher() error {
	pythonLock.Lock()
	defer pythonLock.Unlock()
	moduleDict, err := python.LoadModuleDict("dispatcher")
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Fatalf("Couldn't initialize Python dispatcher")
		python.PyErr_Print()
		return err
	}
	dispatcherClass, err = python.GetItem(moduleDict, "TykDispatcher")
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Fatalf("Couldn't initialize Python dispatcher")
		python.PyErr_Print()
		return err
	}
	return nil
}

// PythonNewDispatcher creates an instance of TykDispatcher.
func PythonNewDispatcher(bundleRootPath string) (coprocess.Dispatcher, error) {
	pythonLock.Lock()
	defer pythonLock.Unlock()
	args, err := python.PyTupleNew(1)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Fatal(err)
		return nil, err
	}
	if err := python.PyTupleSetItem(args, 0, bundleRootPath); err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Error(err)
		python.PyErr_Print()
		return nil, err
	}
	dispatcherInstance, err = python.PyObjectCallObject(dispatcherClass, args)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Error(err)
		python.PyErr_Print()
		return nil, err
	}
	dispatcher := &PythonDispatcher{}
	return dispatcher, nil
}

// PythonSetEnv sets PYTHONPATH, it's called before initializing the interpreter.
func PythonSetEnv(pythonPaths ...string) {
	python.SetPythonPath(pythonPaths)
}

//nolint getBundlePaths will return an array of the available bundle directories:
func getBundlePaths(conf config.Config) []string {
	bundlePath := filepath.Join(conf.MiddlewarePath, "bundles")
	directories := make([]string, 0)
	bundles, _ := ioutil.ReadDir(bundlePath)
	for _, f := range bundles {
		if f.IsDir() {
			fullPath := filepath.Join(bundlePath, f.Name())
			directories = append(directories, fullPath)
		}
	}
	return directories
}

// NewPythonDispatcher wraps all the actions needed for this CP.
func NewPythonDispatcher(conf config.Config) (dispatcher coprocess.Dispatcher, err error) {
	workDir := conf.CoProcessOptions.PythonPathPrefix
	if workDir == "" {
		tykBin, _ := os.Executable()
		workDir = filepath.Dir(tykBin)
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Debugf("Python path prefix isn't set, using '%s'", workDir)
	}
	dispatcherPath := filepath.Join(workDir, "coprocess", "python")
	tykPath := filepath.Join(dispatcherPath, "tyk")
	protoPath := filepath.Join(workDir, "coprocess", "python", "proto")
	bundleRootPath := filepath.Join(conf.MiddlewarePath, "bundles")

	paths := []string{dispatcherPath, tykPath, protoPath, bundleRootPath}

	// initDone is used to signal the end of Python initialization step:
	initDone := make(chan error)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		PythonSetEnv(paths...)
		err := PythonInit(conf.CoProcessOptions.PythonVersion)
		if err != nil {
			initDone <- err
			return
		}
		if err := PythonLoadDispatcher(); err != nil {
			initDone <- err
			return
		}
		dispatcher, err = PythonNewDispatcher(bundleRootPath)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "coprocess",
			}).Error(err)
		}

		initDone <- err
	}()
	err = <-initDone
	return dispatcher, err
}
