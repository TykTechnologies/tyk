package wasm

import (
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/TykTechnologies/logrus"
	wasmerGo "github.com/wasmerio/wasmer-go/wasmer"
)

var ErrModuleNotFound = errors.New("module: 404")

type Wasm struct {
	engine *wasmerGo.Engine
	store  *wasmerGo.Store
	mu     sync.RWMutex
	log    *logrus.Entry
}

func New(lg *logrus.Entry) *Wasm {
	e := wasmerGo.NewEngine()
	s := wasmerGo.NewStore(e)
	return &Wasm{
		engine: e,
		store:  s,
		log:    lg,
	}
}

func (w *Wasm) Compile(name string, wasmBytes []byte) (*wasmerGo.Module, error) {
	m, err := wasmerGo.NewModule(w.store, wasmBytes)
	if err != nil {
		return nil, err
	}
	w.log.WithFields(logrus.Fields{
		"name": name,
	}).Info("Compiled  wasm module")
	return m, nil
}

func (w *Wasm) NewInstance(mw *Config, m *wasmerGo.Module) (*Instance, error) {
	opts := mw.Instance
	state := wasmerGo.NewWasiStateBuilder(opts.ProgramName)
	for _, a := range opts.Arguments {
		state.Argument(a)
	}
	for k, v := range opts.Environments {
		state.Environment(k, v)
	}
	for _, d := range opts.PreopenDirectories {
		state.PreopenDirectory(d)
	}
	for alias, dir := range opts.MapDirectories {
		state.MapDirectory(alias, dir)
	}
	if opts.InheritStdin {
		state.InheritStdin()
	}
	if opts.CaptureStdout {
		state.CaptureStdout()
	}
	if opts.InheritStdout {
		state.InheritStdout()
	}
	if opts.CaptureStderr {
		state.CaptureStderr()
	}
	if opts.InheritStderr {
		state.InheritStderr()
	}
	env, err := state.Finalize()
	if err != nil {
		return nil, err
	}
	o, err := env.GenerateImportObject(w.store, m)
	if err != nil {
		return nil, err
	}
	return NewWasmerInstance(w, o, m, mw), nil
}

func (w *Wasm) CompileFile(path string) (*wasmerGo.Module, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return w.Compile(name(path), b)
}

func name(path string) string {
	return filepath.Base(path)
}
