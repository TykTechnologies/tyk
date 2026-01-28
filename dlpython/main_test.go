package python

import (
	"os"
	"testing"
)

var testVersion = "3.5"

func TestMain(m *testing.M) {
	if versionOverride := os.Getenv("PYTHON_VERSION"); versionOverride != "" {
		testVersion = versionOverride
	}
	os.Exit(m.Run())
}

func TestFindPythonConfig(t *testing.T) {
	_, err := FindPythonConfig("0.0")
	t.Logf("Library path is %s", pythonLibraryPath)
	if err == nil {
		t.Fatal("Should fail when loading a nonexistent Python version")
	}
	pythonVersion, err := FindPythonConfig(testVersion)
	t.Logf("Version is %s", pythonVersion)
	t.Logf("Library path is %s", pythonLibraryPath)
	if err != nil {
		t.Fatalf("Couldn't find Python %s", testVersion)
	}
}

func TestInit(t *testing.T) {
	_, err := FindPythonConfig(testVersion)
	t.Logf("Library path is %s", pythonLibraryPath)
	if err != nil {
		t.Fatalf("Couldn't find Python %s", testVersion)
	}
	err = Init()
	if err != nil {
		t.Fatal("Couldn't load Python runtime")
	}
	// s := C.CString("json")
	moduleName := PyUnicodeFromString("json")
	if moduleName == nil {
		t.Fatal("Couldn't initialize test Python string")
	}
	jsonModule := PyImportImport(moduleName)
	if jsonModule == nil {
		t.Fatal("Couldn't load json module")
	}
}
