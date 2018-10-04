package gorpc

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"
)

// Dispatcher helps constructing HandlerFunc for dispatching across multiple
// functions and/or services.
//
// Dispatcher also automatically registers all request and response types
// for all functions and/or methods registered via AddFunc() and AddService(),
// so there is no need in calling RegisterType() for them.
//
// See examples for details.
type Dispatcher struct {
	serviceMap map[string]*serviceData
}

type serviceData struct {
	sv      reflect.Value
	funcMap map[string]*funcData
}

type funcData struct {
	inNum int
	reqt  reflect.Type
	fv    reflect.Value
}

// NewDispatcher returns new dispatcher.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		serviceMap: make(map[string]*serviceData),
	}
}

// AddFunc registers the given function f under the name funcName.
//
// The function must accept zero, one or two input arguments.
// If the function has two arguments, then the first argument must have
// string type - the server will pass client address in this parameter.
//
// The function must return zero, one or two values.
//   * If the function has two return values, then the second value must have
//     error type - the server will propagate this error to the client.
//
//   * If the function returns only error value, then the server treats it
//     as error, not return value, when sending to the client.
//
// Arbitrary number of functions can be registered in the dispatcher.
//
// See examples for details.
func (d *Dispatcher) AddFunc(funcName string, f interface{}) {
	sd, ok := d.serviceMap[""]
	if !ok {
		sd = &serviceData{
			funcMap: make(map[string]*funcData),
		}
		d.serviceMap[""] = sd
	}

	if _, ok := sd.funcMap[funcName]; ok {
		logPanic("gorpc.Dispatcher: function %s has been already registered", funcName)
	}

	fd := &funcData{
		fv: reflect.Indirect(reflect.ValueOf(f)),
	}
	var err error
	if fd.inNum, fd.reqt, err = validateFunc(funcName, fd.fv, false); err != nil {
		logPanic("gorpc.Disaptcher: %s", err)
	}
	sd.funcMap[funcName] = fd
}

// AddService registers public methods of the given service under
// the given name serviceName.
//
// Since only public methods are registered, the service must have at least
// one public method.
//
// All public methods must conform requirements described in AddFunc().
func (d *Dispatcher) AddService(serviceName string, service interface{}) {
	if serviceName == "" {
		logPanic("gorpc.Dispatcher: serviceName cannot be empty")
	}
	if _, ok := d.serviceMap[serviceName]; ok {
		logPanic("gorpc.Dispatcher: service with name=[%s] has been already registered", serviceName)
	}

	funcMap := make(map[string]*funcData)

	st := reflect.TypeOf(service)
	if st.Kind() == reflect.Struct {
		logPanic("gorpc.Dispatcher: service [%s] must be a pointer to struct, i.e. *%s", serviceName, st)
	}

	for i := 0; i < st.NumMethod(); i++ {
		mv := st.Method(i)

		if mv.PkgPath != "" {
			// skip unexported methods
			continue
		}

		funcName := serviceName + "." + mv.Name
		fd := &funcData{
			fv: mv.Func,
		}
		var err error
		if fd.inNum, fd.reqt, err = validateFunc(funcName, fd.fv, true); err != nil {
			logPanic("gorpc.Dispatcher: %s", err)
		}
		funcMap[mv.Name] = fd
	}

	if len(funcMap) == 0 {
		logPanic("gorpc.Dispatcher: the service %s has no methods suitable for rpc", serviceName)
	}

	d.serviceMap[serviceName] = &serviceData{
		sv:      reflect.ValueOf(service),
		funcMap: funcMap,
	}
}

func validateFunc(funcName string, fv reflect.Value, isMethod bool) (inNum int, reqt reflect.Type, err error) {
	if funcName == "" {
		err = fmt.Errorf("funcName cannot be empty")
		return
	}

	ft := fv.Type()
	if ft.Kind() != reflect.Func {
		err = fmt.Errorf("function [%s] must be a function instead of %s", funcName, ft)
		return
	}

	inNum = ft.NumIn()
	outNum := ft.NumOut()

	dt := 0
	if isMethod {
		dt = 1
	}

	if inNum == 2+dt {
		if ft.In(dt).Kind() != reflect.String {
			err = fmt.Errorf("unexpected type for the first argument of the function [%s]: [%s]. Expected string", funcName, ft.In(dt))
			return
		}
	} else if inNum > 2+dt {
		err = fmt.Errorf("unexpected number of arguments in the function [%s]: %d. Expected 0, 1 (request) or 2 (clientAddr, request)", funcName, inNum-dt)
		return
	}

	if outNum == 2 {
		if !isErrorType(ft.Out(1)) {
			err = fmt.Errorf("unexpected type for the second return value of the function [%s]: [%s]. Expected [%s]", funcName, ft.Out(1), errt)
			return
		}
	} else if outNum > 2 {
		err = fmt.Errorf("unexpected number of return values for the function %s: %d. Expected 0, 1 (response) or 2 (response, error)", funcName, outNum)
		return
	}

	if inNum > dt {
		reqt = ft.In(inNum - 1)
		if err = registerType("request", funcName, reqt); err != nil {
			return
		}
	}

	if outNum > 0 {
		respt := ft.Out(0)
		if !isErrorType(respt) {
			if err = registerType("response", funcName, ft.Out(0)); err != nil {
				return
			}
		}
	}

	return
}

func registerType(s, funcName string, t reflect.Type) error {
	if t.Kind() == reflect.Struct {
		return fmt.Errorf("%s in the function [%s] should be passed by reference, i.e. *%s", s, funcName, t)
	}
	if err := validateType(t); err != nil {
		return fmt.Errorf("%s in the function [%s] cannot contain %s", s, funcName, err)
	}

	t = removePtr(t)
	tv := reflect.New(t)
	if t.Kind() != reflect.Struct {
		tv = reflect.Indirect(tv)
	}

	switch t.Kind() {
	case reflect.Array, reflect.Slice, reflect.Map, reflect.Struct:
		RegisterType(tv.Interface())
	default:
	}

	return nil
}

func removePtr(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t
}

var validatedTypes []*validatedType

type validatedType struct {
	t   reflect.Type
	err *error
}

func validateType(t reflect.Type) (err error) {
	t = removePtr(t)
	for _, vd := range validatedTypes {
		if vd.t == t {
			return *vd.err
		}
	}
	validatedTypes = append(validatedTypes, &validatedType{
		t:   t,
		err: &err,
	})

	switch t.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.UnsafePointer:
		err = fmt.Errorf("%s. Found [%s]", t.Kind(), t)
		return
	case reflect.Array, reflect.Slice:
		if err = validateType(t.Elem()); err != nil {
			err = fmt.Errorf("%s in the %s [%s]", err, t.Kind(), t)
			return
		}
	case reflect.Map:
		if err = validateType(t.Elem()); err != nil {
			err = fmt.Errorf("%s in the value of map [%s]", err, t)
			return
		}
		if err = validateType(t.Key()); err != nil {
			err = fmt.Errorf("%s in the key of map [%s]", err, t)
			return
		}
	case reflect.Struct:
		n := 0
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath == "" {
				if err = validateType(f.Type); err != nil {
					err = fmt.Errorf("%s in the field [%s] of struct [%s]", err, f.Name, t)
					return
				}
				n++
			}
		}
		if n == 0 {
			err = fmt.Errorf("struct without exported fields [%s]", t)
			return
		}
	}

	return err
}

type dispatcherRequest struct {
	Request interface{}
	Name    string
}

type dispatcherResponse struct {
	Response interface{}
	Error    string
}

func init() {
	RegisterType(&dispatcherRequest{})
	RegisterType(&dispatcherResponse{})
}

// NewHandlerFunc returns HandlerFunc serving all the functions and/or services
// registered via AddFunc() and AddService().
//
// The returned HandlerFunc must be assigned to Server.Handler or
// passed to New*Server().
func (d *Dispatcher) NewHandlerFunc() HandlerFunc {
	if len(d.serviceMap) == 0 {
		logPanic("gorpc.Dispatcher: register at least one service before calling HandlerFunc()")
	}

	serviceMap := copyServiceMap(d.serviceMap)

	return func(clientAddr string, request interface{}) interface{} {
		req, ok := request.(*dispatcherRequest)
		if !ok {
			logPanic("gorpc.Dispatcher: unsupported request type received from the client: %T", request)
		}
		return dispatchRequest(serviceMap, clientAddr, req)
	}
}

func copyServiceMap(sm map[string]*serviceData) map[string]*serviceData {
	serviceMap := make(map[string]*serviceData)
	for sk, sv := range sm {
		funcMap := make(map[string]*funcData)
		for fk, fv := range sv.funcMap {
			funcMap[fk] = fv
		}
		serviceMap[sk] = &serviceData{
			sv:      sv.sv,
			funcMap: funcMap,
		}
	}
	return serviceMap
}

func dispatchRequest(serviceMap map[string]*serviceData, clientAddr string, req *dispatcherRequest) *dispatcherResponse {
	callName := strings.SplitN(req.Name, ".", 2)
	if len(callName) != 2 {
		return &dispatcherResponse{
			Error: fmt.Sprintf("gorpc.Dispatcher: cannot split call name into service name and method name [%s]", req.Name),
		}
	}

	serviceName, funcName := callName[0], callName[1]
	s, ok := serviceMap[serviceName]
	if !ok {
		return &dispatcherResponse{
			Error: fmt.Sprintf("gorpc.Dispatcher: unknown service name [%s]", serviceName),
		}
	}

	fd, ok := s.funcMap[funcName]
	if !ok {
		return &dispatcherResponse{
			Error: fmt.Sprintf("gorpc.Dispatcher: unknown method [%s]", req.Name),
		}
	}

	var inArgs []reflect.Value
	if fd.inNum > 0 {
		inArgs = make([]reflect.Value, fd.inNum)

		dt := 0
		if serviceName != "" {
			dt = 1
			inArgs[0] = s.sv
		}
		if fd.inNum == 2+dt {
			inArgs[dt] = reflect.ValueOf(clientAddr)
		}
		if fd.inNum > dt {
			reqv := reflect.ValueOf(req.Request)
			reqt := reflect.TypeOf(req.Request)
			if reqt != fd.reqt {
				return &dispatcherResponse{
					Error: fmt.Sprintf("gorpc.Dispatcher: unexpected request type for method [%s]: %s. Expected %s", req.Name, reqt, fd.reqt),
				}
			}
			inArgs[len(inArgs)-1] = reqv
		}
	}

	outArgs := fd.fv.Call(inArgs)

	resp := &dispatcherResponse{}

	if len(outArgs) == 1 {
		if isErrorType(outArgs[0].Type()) {
			resp.Error = getErrorString(outArgs[0])
		} else {
			resp.Response = outArgs[0].Interface()
		}
	} else if len(outArgs) == 2 {
		resp.Error = getErrorString(outArgs[1])
		if resp.Error == "" {
			resp.Response = outArgs[0].Interface()
		}
	}

	return resp
}

var errt = reflect.TypeOf((*error)(nil)).Elem()

func isErrorType(t reflect.Type) bool {
	return t.Implements(errt)
}

func getErrorString(v reflect.Value) string {
	if v.IsNil() {
		return ""
	}
	return v.Interface().(error).Error()
}

// DispatcherClient is a Client wrapper suitable for calling registered
// functions and/or for calling methods of the registered services.
type DispatcherClient struct {
	c           *Client
	serviceName string
}

// NewFuncClient returns a client suitable for calling functions registered
// via AddFunc().
func (d *Dispatcher) NewFuncClient(c *Client) *DispatcherClient {
	if len(d.serviceMap) == 0 || d.serviceMap[""] == nil {
		logPanic("gorpc.Dispatcher: register at least one function with AddFunc() before calling NewFuncClient()")
	}

	return &DispatcherClient{
		c: c,
	}
}

// NewServiceClient returns a client suitable for calling methods
// of the service with name serviceName registered via AddService().
//
// It is safe creating multiple service clients over a single underlying client.
func (d *Dispatcher) NewServiceClient(serviceName string, c *Client) *DispatcherClient {
	if len(d.serviceMap) == 0 || d.serviceMap[serviceName] == nil {
		logPanic("gorpc.Dispatcher: service [%s] must be registered with AddService() before calling NewServiceClient()", serviceName)
	}

	return &DispatcherClient{
		c:           c,
		serviceName: serviceName,
	}
}

// Call calls the given function.
func (dc *DispatcherClient) Call(funcName string, request interface{}) (response interface{}, err error) {
	return dc.CallTimeout(funcName, request, dc.c.RequestTimeout)
}

// CallTimeout calls the given function and waits for response during the given timeout.
func (dc *DispatcherClient) CallTimeout(funcName string, request interface{}, timeout time.Duration) (response interface{}, err error) {
	req := dc.getRequest(funcName, request)
	resp, err := dc.c.CallTimeout(req, timeout)
	return getResponse(resp, err)
}

// Send sends the given request to the given function and doesn't
// wait for response.
func (dc *DispatcherClient) Send(funcName string, request interface{}) error {
	req := dc.getRequest(funcName, request)
	return dc.c.Send(req)
}

// CallAsync calls the given function asynchronously.
func (dc *DispatcherClient) CallAsync(funcName string, request interface{}) (*AsyncResult, error) {
	req := dc.getRequest(funcName, request)

	innerAr, err := dc.c.CallAsync(req)
	if err != nil {
		return nil, err
	}

	ch := make(chan struct{})
	ar := &AsyncResult{
		Done: ch,
	}

	go func() {
		<-innerAr.Done
		ar.Response, ar.Error = getResponse(innerAr.Response, innerAr.Error)
		close(ch)
	}()

	return ar, nil
}

// DispatcherBatch allows grouping and executing multiple RPCs in a single batch.
//
// DispatcherBatch may be created via DispatcherClient.NewBatch().
type DispatcherBatch struct {
	lock sync.Mutex
	c    *DispatcherClient
	b    *Batch
	ops  []*BatchResult
}

// NewBatch creates new RPC batch for the given DispatcherClient.
//
// It is safe creating multiple concurrent batches from a single client.
func (dc *DispatcherClient) NewBatch() *DispatcherBatch {
	return &DispatcherBatch{
		c: dc,
		b: dc.c.NewBatch(),
	}
}

// Add ads new request to the RPC batch.
//
// The order of batched RPCs execution on the server is unspecified.
//
// All the requests added to the batch are sent to the server at once
// when DispatcherBatch.Call*() is called.
//
// It is safe adding multiple requests to the same batch from concurrently
// running goroutines.
func (b *DispatcherBatch) Add(funcName string, request interface{}) *BatchResult {
	return b.add(funcName, request, false)
}

// AddSkipResponse adds new request to the RPC batch and doesn't care
// about the response.
//
// The order of batched RPCs execution on the server is unspecified.
//
// All the requests added to the batch are sent to the server at once
// when DispatcherBatch.Call*() is called.
//
// It is safe adding multiple requests to the same batch from concurrently
// running goroutines.
func (b *DispatcherBatch) AddSkipResponse(funcName string, request interface{}) {
	b.add(funcName, request, true)
}

func (b *DispatcherBatch) add(funcName string, request interface{}, skipResponse bool) *BatchResult {
	req := b.c.getRequest(funcName, request)

	var br *BatchResult
	b.lock.Lock()
	if !skipResponse {
		br = &BatchResult{
			ctx:  b.b.Add(req),
			done: make(chan struct{}),
		}
		br.Done = br.done
		b.ops = append(b.ops, br)
	} else {
		b.b.AddSkipResponse(req)
	}
	b.lock.Unlock()

	return br
}

// Call calls all the RPCs added via DispatcherBatch.Add().
//
// The order of batched RPCs execution on the server is unspecified.
//
// The caller may read all BatchResult contents returned
// from DispatcherBatch.Add() after the Call returns.
//
// It is guaranteed that all <-BatchResult.Done channels are unblocked after
// the Call returns.
func (b *DispatcherBatch) Call() error {
	return b.CallTimeout(b.c.c.RequestTimeout)
}

// CallTimeout calls all the RPCs added via DispatcherBatch.Add() and waits
// for all the RPC responses during the given timeout.
//
// The caller may read all BatchResult contents returned
// from DispatcherBatch.Add() after the CallTimeout returns.
//
// It is guaranteed that all <-BatchResult.Done channels are unblocked after
// the CallTimeout returns.
func (b *DispatcherBatch) CallTimeout(timeout time.Duration) error {
	b.lock.Lock()
	bb := b.b
	b.b = b.c.c.NewBatch()
	ops := b.ops
	b.ops = nil
	b.lock.Unlock()

	if err := bb.CallTimeout(timeout); err != nil {
		return err
	}

	for _, op := range ops {
		br := op.ctx.(*BatchResult)
		op.Response, op.Error = getResponse(br.Response, br.Error)
		close(op.done)
	}

	return nil
}

func (dc *DispatcherClient) getRequest(funcName string, request interface{}) *dispatcherRequest {
	return &dispatcherRequest{
		Name:    dc.serviceName + "." + funcName,
		Request: request,
	}
}

func getResponse(respv interface{}, err error) (interface{}, error) {
	if err != nil {
		return nil, err
	}
	resp, ok := respv.(*dispatcherResponse)
	if !ok {
		return nil, &ClientError{
			Server: true,
			err:    fmt.Errorf("gorpc.DispatcherClient: unexpected response type: %T. Expected *dispatcherResponse", respv),
		}
	}
	if resp.Error != "" {
		return nil, &ClientError{
			Server: true,
			err:    errors.New(resp.Error),
		}
	}
	return resp.Response, nil
}
