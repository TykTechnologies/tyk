package python

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"
)

// Verifies: STK-REQ-048, SYS-REQ-136, SW-REQ-123
// STK-REQ-048:STK-REQ-048-AC-01:acceptance
// SYS-REQ-136:nominal:nominal
// SYS-REQ-136:error_handling:negative
// SW-REQ-123:nominal:nominal
// SW-REQ-123:boundary:nominal
// SW-REQ-123:error_handling:negative
// STK-REQ-048:error_handling:negative
func TestDLPythonReqProof_FindPythonConfig(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		setup      func(t *testing.T) string
		custom     string
		want       string
		wantErr    string
		wantLib    string
		wantCfgBin string
	}{
		{
			name:    "empty PATH returns explicit error",
			setup:   func(t *testing.T) string { return "" },
			wantErr: errEmptyPath.Error(),
		},
		{
			name: "missing python config returns explicit error",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "bin")
			},
			wantErr: "No Python installations found",
		},
		{
			name: "custom missing version returns explicit error",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeFakePythonConfig(t, dir, "3.10")
				return filepath.Join(dir, "bin")
			},
			custom:  "3.11",
			wantErr: "No python-config was found for the specified version",
		},
		{
			name: "default selects latest discovered version",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeFakePythonConfig(t, dir, "3.9")
				writeFakePythonConfig(t, dir, "3.11")
				writeFakePythonLib(t, dir, "3.9")
				writeFakePythonLib(t, dir, "3.11")
				return filepath.Join(dir, "bin")
			},
			want:       "3.11",
			wantLib:    "3.11",
			wantCfgBin: "python3.11-config",
		},
		{
			name: "custom version selects matching config",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeFakePythonConfig(t, dir, "3.9")
				writeFakePythonConfig(t, dir, "3.11")
				writeFakePythonLib(t, dir, "3.9")
				writeFakePythonLib(t, dir, "3.11")
				return filepath.Join(dir, "bin")
			},
			custom:     "3.9",
			want:       "3.9",
			wantLib:    "3.9",
			wantCfgBin: "python3.9-config",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restoreDLPythonGlobals(t)
			paths = tc.setup(t)

			got, err := FindPythonConfig(tc.custom)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("FindPythonConfig error = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("FindPythonConfig returned error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("FindPythonConfig version = %q, want %q", got, tc.want)
			}
			if !strings.HasSuffix(pythonConfigPath, filepath.Join("bin", tc.wantCfgBin)) {
				t.Fatalf("pythonConfigPath = %q, want suffix %q", pythonConfigPath, tc.wantCfgBin)
			}
			if !strings.Contains(filepath.Base(pythonLibraryPath), tc.wantLib) {
				t.Fatalf("pythonLibraryPath = %q, want version %q", pythonLibraryPath, tc.wantLib)
			}
		})
	}
}

// Verifies: STK-REQ-048, SYS-REQ-136, SW-REQ-123
// STK-REQ-048:STK-REQ-048-AC-02:acceptance
// STK-REQ-048:STK-REQ-048-AC-03:acceptance
// SYS-REQ-136:nominal:nominal
// SW-REQ-123:nominal:nominal
// SW-REQ-123:boundary:nominal
// SW-REQ-123:error_handling:nominal
// MCDC SYS-REQ-136: dynamic_python_loader_operation_requested=T, dynamic_python_loader_result_determined=T => TRUE
func TestDLPythonReqProof_InitBindingsAndHelpers(t *testing.T) {
	restoreDLPythonGlobals(t)

	dir := t.TempDir()
	writeFakePythonConfig(t, dir, "3.11")
	writeFakePythonLib(t, dir, "3.11")
	paths = filepath.Join(dir, "bin")

	if got, err := FindPythonConfig("3.11"); err != nil || got != "3.11" {
		t.Fatalf("FindPythonConfig = %q, %v; want 3.11, nil", got, err)
	}
	if err := Init(); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	if Py_IsInitialized() == 0 {
		t.Fatal("fake Python runtime was not initialized")
	}

	moduleObject := PyUnicodeFromString("json")
	if moduleObject == nil {
		t.Fatal("PyUnicodeFromString returned nil")
	}
	if PyImportImport(moduleObject) == nil {
		t.Fatal("PyImportImport returned nil")
	}
	if ToPyObject(moduleObject) == nil {
		t.Fatal("ToPyObject returned nil")
	}

	SetPythonPath([]string{"/opt/one", "/opt/two"})
	if got := os.Getenv(pythonPathKey); got != "/opt/one:/opt/two" {
		t.Fatalf("PYTHONPATH = %q, want merged paths", got)
	}
	if dict, err := LoadModuleDict("json"); err != nil || dict == nil {
		t.Fatalf("LoadModuleDict = %v, %v; want nonnil, nil", dict, err)
	}
	if item, err := GetItem(unsafe.Pointer(moduleObject), "loads"); err != nil || item == nil {
		t.Fatalf("GetItem = %v, %v; want nonnil, nil", item, err)
	}
	PyRunSimpleString("x = 1")
	tup, err := PyTupleNew(2)
	if err != nil {
		t.Fatalf("PyTupleNew returned error: %v", err)
	}
	if err := PyTupleSetItem(tup, 0, "value"); err != nil {
		t.Fatalf("PyTupleSetItem string returned error: %v", err)
	}
	if err := PyTupleSetItem(tup, 1, unsafe.Pointer(moduleObject)); err != nil {
		t.Fatalf("PyTupleSetItem object returned error: %v", err)
	}
	if got, err := PyTupleGetItem(tup, 0); err != nil || got == nil {
		t.Fatalf("PyTupleGetItem = %v, %v; want nonnil, nil", got, err)
	}
	if got, err := PyObjectCallObject(unsafe.Pointer(moduleObject), tup); err != nil || got == nil {
		t.Fatalf("PyObjectCallObject = %v, %v; want nonnil, nil", got, err)
	}
	if got, err := PyObjectGetAttr(unsafe.Pointer(moduleObject), "loads"); err != nil || got == nil {
		t.Fatalf("PyObjectGetAttr = %v, %v; want nonnil, nil", got, err)
	}
	if got, err := PyObjectGetAttr(unsafe.Pointer(moduleObject), 10); err != nil || got != nil {
		t.Fatalf("PyObjectGetAttr unsupported attr = %v, %v; want nil, nil", got, err)
	}
	byteObj, err := PyBytesFromString([]byte("payload"))
	if err != nil {
		t.Fatalf("PyBytesFromString returned error: %v", err)
	}
	if got, err := PyBytesAsString(byteObj, len("payload")); err != nil || string(got) != "payload" {
		t.Fatalf("PyBytesAsString = %q, %v; want payload, nil", string(got), err)
	}
	if got := PyLongAsLong(unsafe.Pointer(moduleObject)); got != 42 {
		t.Fatalf("PyLongAsLong = %d, want 42", got)
	}
	PyIncRef(unsafe.Pointer(moduleObject))
	PyDecRef(unsafe.Pointer(moduleObject))
}

// Verifies: SW-REQ-123
func restoreDLPythonGlobals(t *testing.T) {
	t.Helper()

	oldPaths := paths
	oldConfig := pythonConfigPath
	oldLibrary := pythonLibraryPath
	t.Cleanup(func() {
		paths = oldPaths
		pythonConfigPath = oldConfig
		pythonLibraryPath = oldLibrary
	})
}

// Verifies: SW-REQ-123
func writeFakePythonConfig(t *testing.T, root string, version string) {
	t.Helper()

	binDir := filepath.Join(root, "bin")
	libDir := filepath.Join(root, "lib")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatalf("create lib dir: %v", err)
	}
	path := filepath.Join(binDir, "python"+version+"-config")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' '-L%s -lpython%s'\n", libDir, version)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake python-config: %v", err)
	}
}

// Verifies: SW-REQ-123
func writeFakePythonLib(t *testing.T, root string, version string) {
	t.Helper()

	libDir := filepath.Join(root, "lib")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatalf("create lib dir: %v", err)
	}

	var libName string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		libName = "libpython" + version + ".dylib"
		args = []string{"-dynamiclib", "-o", filepath.Join(libDir, libName)}
	case "linux":
		libName = "libpython" + version + ".so"
		args = []string{"-shared", "-fPIC", "-o", filepath.Join(libDir, libName)}
	default:
		t.Skipf("fake dynamic library unsupported on %s", runtime.GOOS)
	}

	sourcePath := filepath.Join(root, "fake_python.c")
	if err := os.WriteFile(sourcePath, []byte(fakePythonCSource), 0o644); err != nil {
		t.Fatalf("write fake Python source: %v", err)
	}
	args = append(args, sourcePath)
	cmd := exec.Command("gcc", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build fake Python library: %v\n%s", err, out)
	}
}

const fakePythonCSource = `
#include <stdlib.h>
#include <string.h>

typedef struct _pyobject {} PyObject;
typedef struct _pythreadstate {} PyThreadState;
typedef int PyGILState_STATE;

static PyObject object_one;
static PyThreadState thread_state;
static char bytes_buf[1024];
static int initialized = 0;

PyObject* PyObject_GetAttr(PyObject* arg0, PyObject* arg1) { return &object_one; }
PyObject* PyBytes_FromStringAndSize(char* arg0, long arg1) {
    memset(bytes_buf, 0, sizeof(bytes_buf));
    if (arg1 > 1023) { arg1 = 1023; }
    memcpy(bytes_buf, arg0, arg1);
    return (PyObject*)bytes_buf;
}
char* PyBytes_AsString(PyObject* arg0) { return (char*)arg0; }
PyObject* PyUnicode_FromString(char* u) { return &object_one; }
long int PyLong_AsLong(PyObject* arg0) { return 42; }
PyObject* PyTuple_New(long size) { return &object_one; }
PyObject* PyTuple_GetItem(PyObject* arg0, long arg1) { return &object_one; }
int PyTuple_SetItem(PyObject* arg0, long arg1, PyObject* arg2) { return 0; }
PyObject* PyDict_GetItemString(PyObject* dp, char* key) { return &object_one; }
PyObject* PyModule_GetDict(PyObject* arg0) { return &object_one; }
PyGILState_STATE PyGILState_Ensure() { return 7; }
void PyGILState_Release(PyGILState_STATE arg0) {}
int PyRun_SimpleStringFlags(char* arg0, void* arg1) { return 0; }
void PyErr_Print() {}
void Py_Initialize() { initialized = 1; }
int Py_IsInitialized() { return initialized; }
PyThreadState* PyEval_SaveThread() { return &thread_state; }
void PyEval_InitThreads() {}
PyObject* PyImport_Import(PyObject* name) { return &object_one; }
PyObject* PyObject_CallObject(PyObject* callable_object, PyObject* args) { return &object_one; }
void Py_IncRef(PyObject* object) {}
void Py_DecRef(PyObject* object) {}
`
