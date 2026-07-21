package log

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

var (
	outputRegistry = map[Output]outputFactory{
		OutputStdout: func(_ json.RawMessage) (io.Writer, error) {
			return os.Stdout, nil
		},
		OutputStderr: func(_ json.RawMessage) (io.Writer, error) {
			return os.Stderr, nil
		},
	}
)

type (
	outputFactory func(opts json.RawMessage) (io.Writer, error)
	Output        string
)

const (
	OutputStdout Output = "stdout"
	OutputStderr Output = "stderr"
)

func MakeOutput(output Output, opts json.RawMessage) (io.Writer, error) {
	if fn, ok := outputRegistry[output]; !ok {
		return nil, fmt.Errorf("unknown output %q for logger", output)
	} else {
		return fn(opts)
	}
}
