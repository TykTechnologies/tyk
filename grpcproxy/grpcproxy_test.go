// +build !race

package grpcproxy

import (
	"fmt"
	"os"
	"os/exec"
	gr "runtime"
	"testing"

	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/satori/go.uuid"
)

func generatePlugin() (string, error) {
	pName := fmt.Sprintf("%v.so", uuid.NewV4().String())
	fileArg := fmt.Sprintf("-o=%v", pName)

	cmd := exec.Command("go", "build", "--tags='dummy'", "--buildmode=plugin", fileArg)
	cmd.Dir = "../plugin_build"

	err := cmd.Run()
	if err != nil {
		return "", err
	}

	return pName, nil
}

func TestLoadGRPCPRoxy(t *testing.T) {
	f, err := generatePlugin()
	pluginPath := fmt.Sprintf("../plugin_build/%v", f)
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
