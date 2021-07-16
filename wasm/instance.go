package wasm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	wasmerGo "github.com/wasmerio/wasmer-go/wasmer"
	"mosn.io/proxy-wasm-go-host/proxywasm/common"
	v1 "mosn.io/proxy-wasm-go-host/proxywasm/v1"
)

var (
	ErrAddrOverflow         = errors.New("addr overflow")
	ErrInstanceNotStart     = errors.New("instance has not started")
	ErrInstanceAlreadyStart = errors.New("instance has already started")
	ErrInvalidParam         = errors.New("invalid param")
	ErrRegisterNotFunc      = errors.New("register a non-func object")
	ErrRegisterArgNum       = errors.New("register func with invalid arg num")
	ErrRegisterArgType      = errors.New("register func with invalid arg type")
)

var _ common.WasmInstance = (*Instance)(nil)

type Instance struct {
	vm           *Wasm
	importObject *wasmerGo.ImportObject
	instance     *wasmerGo.Instance
	module       *wasmerGo.Module
	mw           *Config

	lock     sync.Mutex
	started  uint32
	refCount int
	stopCond *sync.Cond

	// for cache
	memory    *wasmerGo.Memory
	funcCache sync.Map // string -> *wasmerGo.Function

	// user-defined data
	data interface{}
}

func NewWasmerInstance(vm *Wasm,
	imp *wasmerGo.ImportObject,
	module *wasmerGo.Module,
	mw *Config,
) *Instance {
	ins := &Instance{
		vm:           vm,
		importObject: imp,
		module:       module,
		mw:           mw,
	}
	ins.stopCond = sync.NewCond(&ins.lock)
	v1.RegisterImports(ins)
	return ins
}

func (w *Instance) GetData() interface{} {
	return w.data
}

func (w *Instance) SetData(data interface{}) {
	w.data = data
}

func (w *Instance) Acquire() bool {
	w.lock.Lock()
	defer w.lock.Unlock()

	if !w.checkStart() {
		return false
	}

	w.refCount++

	return true
}

func (w *Instance) Release() {
	w.lock.Lock()
	w.refCount--

	if w.refCount <= 0 {
		w.stopCond.Broadcast()
	}
	w.lock.Unlock()
}

func (w *Instance) Lock(data interface{}) {
	w.lock.Lock()
	w.data = data
}

func (w *Instance) Unlock() {
	w.data = nil
	w.lock.Unlock()
}

func (w *Instance) GetModule() common.WasmModule {
	return nil
}

func (w *Instance) Start() error {
	inst, err := wasmerGo.NewInstance(w.module, w.importObject)
	if err != nil {
		return err
	}
	w.instance = inst
	f, err := w.instance.Exports.GetFunction("_start")
	if err != nil {
		return err
	}

	_, err = f()
	if err != nil {
		w.HandleError(err)
		return err
	}
	atomic.StoreUint32(&w.started, 1)
	return nil
}

func (w *Instance) Stop() {
	go func() {
		w.lock.Lock()
		for w.refCount > 0 {
			w.stopCond.Wait()
		}
		_ = atomic.CompareAndSwapUint32(&w.started, 1, 0)
		w.lock.Unlock()
	}()
}

// return true is Instance is started, false if not started.
func (w *Instance) checkStart() bool {
	return atomic.LoadUint32(&w.started) == 1
}

func (w *Instance) RegisterFunc(namespace string, funcName string, f interface{}) error {
	if w.checkStart() {
		return ErrInstanceAlreadyStart
	}

	if namespace == "" || funcName == "" {
		return ErrInvalidParam
	}

	if f == nil || reflect.ValueOf(f).IsNil() {
		return ErrInvalidParam
	}

	if reflect.TypeOf(f).Kind() != reflect.Func {
		return ErrRegisterNotFunc
	}

	funcType := reflect.TypeOf(f)

	argsNum := funcType.NumIn()
	if argsNum < 1 {
		return ErrRegisterArgNum
	}

	argsKind := make([]*wasmerGo.ValueType, argsNum-1)
	for i := 1; i < argsNum; i++ {
		argsKind[i-1] = convertFromGoType(funcType.In(i))
	}

	retsNum := funcType.NumOut()
	retsKind := make([]*wasmerGo.ValueType, retsNum)
	for i := 0; i < retsNum; i++ {
		retsKind[i] = convertFromGoType(funcType.Out(i))
	}

	fwasmer := wasmerGo.NewFunction(
		w.vm.store,
		wasmerGo.NewFunctionType(argsKind, retsKind),
		func(args []wasmerGo.Value) (callRes []wasmerGo.Value, err error) {
			defer func() {
				if r := recover(); r != nil {
					callRes = nil
					err = fmt.Errorf("panic [%v] when calling func [%v]", r, funcName)
				}
			}()

			aa := make([]reflect.Value, 1+len(args))
			aa[0] = reflect.ValueOf(w)

			for i, arg := range args {
				aa[i+1] = convertToGoTypes(arg)
			}

			callResult := reflect.ValueOf(f).Call(aa)

			ret := convertFromGoValue(callResult[0])

			return []wasmerGo.Value{ret}, nil
		},
	)

	w.importObject.Register(namespace, map[string]wasmerGo.IntoExtern{
		funcName: fwasmer,
	})

	return nil
}

func (w *Instance) Malloc(size int32) (uint64, error) {
	if !w.checkStart() {
		return 0, ErrInstanceNotStart
	}

	malloc, err := w.GetExportsFunc("malloc")
	if err != nil {
		return 0, err
	}

	addr, err := malloc.Call(size)
	if err != nil {
		w.HandleError(err)
		return 0, err
	}

	return uint64(addr.(int32)), nil
}

func (w *Instance) GetExportsFunc(funcName string) (common.WasmFunction, error) {
	if !w.checkStart() {
		return nil, ErrInstanceNotStart
	}

	if v, ok := w.funcCache.Load(funcName); ok {
		return v.(*wasmerGo.Function), nil
	}

	f, err := w.instance.Exports.GetRawFunction(funcName)
	if err != nil {
		return nil, err
	}

	w.funcCache.Store(funcName, f)

	return f, nil
}

func (w *Instance) GetExportsMem(memName string) ([]byte, error) {
	if !w.checkStart() {
		return nil, ErrInstanceNotStart
	}

	if w.memory == nil {
		m, err := w.instance.Exports.GetMemory(memName)
		if err != nil {
			return nil, err
		}

		w.memory = m
	}

	return w.memory.Data(), nil
}

func (w *Instance) GetMemory(addr uint64, size uint64) ([]byte, error) {
	mem, err := w.GetExportsMem("memory")
	if err != nil {
		return nil, err
	}

	if int(addr) > len(mem) || int(addr+size) > len(mem) {
		return nil, ErrAddrOverflow
	}

	return mem[addr : addr+size], nil
}

func (w *Instance) PutMemory(addr uint64, size uint64, content []byte) error {
	mem, err := w.GetExportsMem("memory")
	if err != nil {
		return err
	}

	if int(addr) > len(mem) || int(addr+size) > len(mem) {
		return ErrAddrOverflow
	}

	copySize := uint64(len(content))
	if size < copySize {
		copySize = size
	}

	copy(mem[addr:], content[:copySize])

	return nil
}

func (w *Instance) GetByte(addr uint64) (byte, error) {
	mem, err := w.GetExportsMem("memory")
	if err != nil {
		return 0, err
	}

	if int(addr) > len(mem) {
		return 0, ErrAddrOverflow
	}

	return mem[addr], nil
}

func (w *Instance) PutByte(addr uint64, b byte) error {
	mem, err := w.GetExportsMem("memory")
	if err != nil {
		return err
	}

	if int(addr) > len(mem) {
		return ErrAddrOverflow
	}

	mem[addr] = b

	return nil
}

func (w *Instance) GetUint32(addr uint64) (uint32, error) {
	mem, err := w.GetExportsMem("memory")
	if err != nil {
		return 0, err
	}

	if int(addr) > len(mem) || int(addr+4) > len(mem) {
		return 0, ErrAddrOverflow
	}

	return binary.LittleEndian.Uint32(mem[addr:]), nil
}

func (w *Instance) PutUint32(addr uint64, value uint32) error {
	mem, err := w.GetExportsMem("memory")
	if err != nil {
		return err
	}

	if int(addr) > len(mem) || int(addr+4) > len(mem) {
		return ErrAddrOverflow
	}

	binary.LittleEndian.PutUint32(mem[addr:], value)

	return nil
}

func (w *Instance) HandleError(err error) {
	var trapError *wasmerGo.TrapError
	if !errors.As(err, &trapError) {
		return
	}
}
