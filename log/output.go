package log

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

var (
	// if you are planning to extend outputRegistry, see Benchmark_Logger_Slow_Sink.
	// Sink has to be wrapped with AsyncSink, which holds an internal queue
	// and has a defined strategy on how to deal with delayed logs (drop, wait...)
	outputRegistry = map[Output]outputFactory{
		OutputStdout: func(opts json.RawMessage) (io.Writer, error) {
			if err := rejectOutputOptions(OutputStdout, opts); err != nil {
				return nil, err
			}
			return os.Stdout, nil
		},
		OutputStderr: func(opts json.RawMessage) (io.Writer, error) {
			if err := rejectOutputOptions(OutputStderr, opts); err != nil {
				return nil, err
			}
			return os.Stderr, nil
		},
	}
)

func rejectOutputOptions(output Output, opts json.RawMessage) error {
	switch strings.TrimSpace(string(opts)) {
	case "", "null", "{}":
		return nil
	}
	return fmt.Errorf("output %q takes no output_options", output)
}

type (
	outputFactory func(opts json.RawMessage) (io.Writer, error)
	Output        string
)

const (
	OutputStdout Output = "stdout"
	OutputStderr Output = "stderr"
)

func MakeOutput(output Output, opts json.RawMessage) (io.Writer, error) {
	if fn, ok := outputRegistry[output]; ok {
		return fn(opts)
	}

	return nil, fmt.Errorf("unknown output %q for logger", output)
}
