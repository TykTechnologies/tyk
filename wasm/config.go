package wasm

type InstanceConfig struct {
	ProgramName        string
	Arguments          []string
	Environments       map[string]string
	PreopenDirectories []string
	MapDirectories     map[string]string
	InheritStdin       bool
	CaptureStdout      bool
	InheritStdout      bool
	CaptureStderr      bool
	InheritStderr      bool
}

type Config struct {
	Name     string
	Module   string
	Instance InstanceConfig
	Plugin   map[string]interface{}
}
