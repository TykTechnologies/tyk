package test

import "os"

func GetPythonVersion() string {
	pythonVersion := os.Getenv("PYTHON_VERSION")
	if pythonVersion == "" {
		pythonVersion = "3.5"
	}
	return pythonVersion
}
