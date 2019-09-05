package gateway

import (
	"C"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"

	"github.com/Sirupsen/logrus"

	"errors"
	"fmt"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/coprocess"

	"github.com/golang/protobuf/proto"
	python "github.com/matiasinsaurralde/dlpython"
)

const CoProcessName = apidef.PythonDriver

var (
	MessageType        = coprocess.ProtobufMessage
	dispatcherClass    unsafe.Pointer
	dispatcherInstance unsafe.Pointer
)

// PythonDispatcher implements a coprocess.Dispatcher
type PythonDispatcher struct {
	coprocess.Dispatcher
	mu sync.Mutex
}

// Dispatch takes a CoProcessMessage and sends it to the CP.
func (d *PythonDispatcher) Dispatch(object *coprocess.Object) (*coprocess.Object, error) {
	// Prepare the PB object:

	objectMsg, err := proto.Marshal(object)
	if err != nil {
		return nil, err
	}

	// Find the dispatch_hook stuff (this should be done during init)
	dispatchHookFunc, err := python.PyObjectGetAttr(dispatcherInstance, "dispatch_hook")
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Error(err)
	}

	objectBytes, err := python.PyBytesFromString(objectMsg)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Error(err)
	}

	args, err := python.PyTupleNew(1)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Fatal(err)
	}

	python.PyTupleSetItem(args, 0, objectBytes)
	result, err := python.PyObjectCallObject(dispatchHookFunc, args)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Error(err)
		return nil, err
	}

	newObjectPtr, err := python.PyTupleGetItem(result, 0)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Error(err)
		return nil, err
	}

	newObjectBytes, err := python.PyBytesAsString(newObjectPtr)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Error(err)
		return nil, err
	}

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
	d.mu.Lock()
	go func() {
		runtime.LockOSThread()

		dispatcherLoadBundle, err := python.PyObjectGetAttr(dispatcherInstance, "load_bundle")
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "python",
			}).Error(err)
		}

		args, err := python.PyTupleNew(1)
		if err != nil {
			log.WithFields(logrus.Fields{
				"prefix": "python",
			}).Error(err)
		}
		python.PyTupleSetItem(args, 0, basePath)
		python.PyObjectCallObject(dispatcherLoadBundle, args)
	}()
}

// PythonInit initializes the Python interpreter.
func PythonInit() error {
	ver := config.Global().CoProcessOptions.PythonVersion
	// TODO: disable Python functionality (should we set a default one?)
	if ver == "" {
		return errors.New("Python version is not set")
	}

	err := python.FindPythonConfig(ver)
	if err != nil {
		return fmt.Errorf("Python version '%s' doesn't exist", ver)
	}
	err = python.Init()
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Fatal("Couldn't initialize Python")
	}
	log.WithFields(logrus.Fields{
		"prefix": "coprocess",
	}).Infof("Python version '%s' loaded", ver)
	return nil
}

// PythonLoadDispatcher creates reference to the dispatcher class.
func PythonLoadDispatcher() {
	moduleDict, err := python.LoadModuleDict("dispatcher")
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Fatalf("Couldn't initialize Python dispatcher")
	}
	dispatcherClass, err = python.GetItem(moduleDict, "TykDispatcher")
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Fatalf("Couldn't initialize Python dispatcher")
	}
}

// PythonNewDispatcher creates an instance of TykDispatcher.
func PythonNewDispatcher(bundleRootPath string) (coprocess.Dispatcher, error) {
	args, err := python.PyTupleNew(1)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Fatal(err)
	}
	python.PyTupleSetItem(args, 0, bundleRootPath)
	dispatcherInstance, err = python.PyObjectCallObject(dispatcherClass, args)
	if err != nil {
		log.WithFields(logrus.Fields{
			"prefix": "python",
		}).Fatal(err)
	}
	dispatcher := &PythonDispatcher{mu: sync.Mutex{}}
	return dispatcher, nil
}

// PythonSetEnv sets PYTHONPATH, it's called before initializing the interpreter.
func PythonSetEnv(pythonPaths ...string) {
	if config.Global().CoProcessOptions.PythonPathPrefix == "" {
		log.WithFields(logrus.Fields{
			"prefix": "coprocess",
		}).Warning("Python path prefix isn't set (check \"python_path_prefix\" in tyk.conf)")
	}
	python.SetPythonPath(pythonPaths)
}

// getBundlePaths will return an array of the available bundle directories:
func getBundlePaths() []string {
	bundlePath := filepath.Join(config.Global().MiddlewarePath, "bundles")
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

// NewCoProcessDispatcher wraps all the actions needed for this CP.
func NewCoProcessDispatcher() (dispatcher coprocess.Dispatcher, err error) {
	// MessageType sets the default message type.
	// MessageType = coprocess.ProtobufMessage

	// CoProcessName declares the driver name.
	// CoProcessName = apidef.PythonDriver

	workDir := config.Global().CoProcessOptions.PythonPathPrefix

	dispatcherPath := filepath.Join(workDir, "coprocess", "python")
	tykPath := filepath.Join(dispatcherPath, "tyk")
	protoPath := filepath.Join(workDir, "coprocess", "python", "proto")
	bundleRootPath := filepath.Join(config.Global().MiddlewarePath, "bundles")

	paths := []string{dispatcherPath, tykPath, protoPath, bundleRootPath}

	// initDone is used to signal the end of Python initialization step:
	initDone := make(chan error)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		PythonSetEnv(paths...)
		err := PythonInit()
		if err != nil {
			initDone <- err
			return
		}
		PythonLoadDispatcher()
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
