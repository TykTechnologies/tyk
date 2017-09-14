package grpcproxy

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
)

var buildScript string = `#!/bin/bash
cd ../plugin_build
go build --tags="dummy" --buildmode=plugin -o plugin.so
`

func generatePlugin() error {
	scriptName := "build_plugin.sh"
	defer os.Remove(scriptName)
	err := ioutil.WriteFile(scriptName, []byte(buildScript), 0755)
	if err != nil {
		return err
	}

	cmd := exec.Command(fmt.Sprintf("./%v", scriptName), "")
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}

	return nil
}

func TestLoadGRPCPRoxy(t *testing.T) {
	pluginPath := "../plugin_build/plugin.so"
	defer os.Remove(pluginPath)

	err := generatePlugin()
	if err != nil {
		t.Fatal(err)
	}

	testMux := runtime.NewServeMux()
	err = LoadGRPCProxyPlugin(pluginPath, "http://localhost", testMux)
	if err != nil {
		t.Fatal(err)
	}
}
