package grpcproxy

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	gr "runtime"
	"testing"

	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/satori/go.uuid"
)

var buildScript string = `#!/bin/bash
cd ../plugin_build
go build --tags="dummy" --buildmode=plugin -o $1.so
`

func generatePlugin() (string, error) {
	scriptName := "build_plugin.sh"
	defer os.Remove(scriptName)
	err := ioutil.WriteFile(scriptName, []byte(buildScript), 0755)
	if err != nil {
		return "", err
	}

	uid := uuid.NewV4().String()
	cmd := exec.Command(fmt.Sprintf("./%v", scriptName), uid)
	_, err = cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	return uid, nil
}

func TestLoadGRPCPRoxy(t *testing.T) {
	f, err := generatePlugin()
	pluginPath := fmt.Sprintf("../plugin_build/%v.so", f)
	defer os.Remove(pluginPath)
	if err != nil {
		t.Fatal(err)
	}

	testMux := runtime.NewServeMux()
	err = LoadGRPCProxyPlugin(pluginPath, "http://localhost", testMux)
	if strings.Contains(gr.Version(), "go1.8") {
		if err == nil {
			t.Fatal("Load should have thrown error, but it passed")
		}
	} else {
		if err != nil {
			t.Fatal(err)
		}
	}

}
