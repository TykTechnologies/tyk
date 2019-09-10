package python

import (
	"fmt"
	"os"
	"testing"
)

var testVersion = "3.5"

func init() {
	if versionOverride := os.Getenv("PYTHON_VERSION"); versionOverride != "" {
		testVersion = versionOverride
	}
	fmt.Printf("Using Python %s for tests\n", testVersion)
}

func TestFindPythonConfig(t *testing.T) {
	_, err := FindPythonConfig("0.0")
	t.Logf("Library path is %s", pythonLibraryPath)
	if err == nil {
		t.Fatal("Should fail when loading a nonexistent Python version")
	}
	_, err = FindPythonConfig(testVersion)
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
