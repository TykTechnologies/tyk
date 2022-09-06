// package pipe initializes, configures and runs a pipeline
package pipe

import (
	"bytes"
	"encoding/json"
	"github.com/jensneuse/pipeline/pkg/step"
	"io"
)

// Step is a pipeline step which takes an io.Reader as well as an io.Writer as arguments
// The previous (or first) pipeline step will pipe its result to the reader of the next (or final) pipeline step.
// The step is expected to write its result to the writer so that the next (or final) step can proceed doing its work.
type Step interface {
	Invoke(reader io.Reader, writer io.Writer) error
}

// Config is the Configuration Object to setup all steps
type Config struct {
	Steps []StepConfig `json:"steps"`
}

// StepConfig is the object to hold the kind and config of each step
type StepConfig struct {
	Kind   string          `json:"kind"`
	Config json.RawMessage `json:"config"`
}

// Pipeline holds all steps and executes them on after each other
type Pipeline struct {
	Steps []Step
}

// FromConfig takes a StepConfig in JSON format and creates an executable Pipeline from it
func (p *Pipeline) FromConfig(reader io.Reader) error {
	var config Config
	err := json.NewDecoder(reader).Decode(&config)
	if err != nil {
		return err
	}
	for i := range config.Steps {
		var next Step
		switch config.Steps[i].Kind {
		case "JSON":
			next, err = step.UnmarshalJsonStep(bytes.NewReader(config.Steps[i].Config))
		case "HTTP":
			next, err = step.UnmarshalHttpStep(bytes.NewReader(config.Steps[i].Config))
		case "NOOP":
			next = step.NoOpStep{}
		}
		if err != nil {
			return err
		}
		p.Steps = append(p.Steps, next)
	}
	return nil
}

// Run starts the pipeline
// It takes the input from the reader and pipes it into the first step
// The result written to the writer of the last step will be emitted to the writer passed to Run
func (p *Pipeline) Run (reader io.Reader,writer io.Writer) error {

	readBuf := bytes.Buffer{}
	writeBuf := bytes.Buffer{}

	_,err := readBuf.ReadFrom(reader)
	if err != nil {
		return err
	}

	for i := range p.Steps {
		err = p.Steps[i].Invoke(&readBuf,&writeBuf)
		if err != nil {
			return err
		}
		readBuf.Reset()
		_,err = writeBuf.WriteTo(&readBuf)
		if err != nil {
			return err
		}
		writeBuf.Reset()
	}

	_,err = readBuf.WriteTo(writer)
	return err
}