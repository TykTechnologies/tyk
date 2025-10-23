package grpc

import (
	"context"
	"testing"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/coprocess"
)

// LegacyDispatcher simulates an old dispatcher that only implements the base Dispatcher interface
// without DispatchWithContext support
type LegacyDispatcher struct {
	coprocess.Dispatcher
	dispatchCalled bool
}

func (d *LegacyDispatcher) Dispatch(object *coprocess.Object) (*coprocess.Object, error) {
	d.dispatchCalled = true
	// Simulate processing
	if object.Request.SetHeaders == nil {
		object.Request.SetHeaders = make(map[string]string)
	}
	object.Request.SetHeaders["X-Legacy-Processed"] = "true"
	return object, nil
}

func (d *LegacyDispatcher) DispatchEvent(eventJSON []byte)                                      {}
func (d *LegacyDispatcher) DispatchObject(object *coprocess.Object) (*coprocess.Object, error) { return d.Dispatch(object) }
func (d *LegacyDispatcher) LoadModules()                                                        {}
func (d *LegacyDispatcher) HandleMiddlewareCache(b *apidef.BundleManifest, basePath string)    {}
func (d *LegacyDispatcher) Reload()                                                             {}

// ModernDispatcher implements DispatcherWithContext (which embeds Dispatcher)
type ModernDispatcher struct {
	coprocess.DispatcherWithContext
	dispatchCalled            bool
	dispatchWithContextCalled bool
}

func (d *ModernDispatcher) Dispatch(object *coprocess.Object) (*coprocess.Object, error) {
	d.dispatchCalled = true
	return d.DispatchWithContext(context.Background(), object)
}

func (d *ModernDispatcher) DispatchWithContext(ctx context.Context, object *coprocess.Object) (*coprocess.Object, error) {
	d.dispatchWithContextCalled = true
	// Simulate processing with context
	if object.Request.SetHeaders == nil {
		object.Request.SetHeaders = make(map[string]string)
	}
	object.Request.SetHeaders["X-Modern-Processed"] = "true"
	
	// Check if context is valid
	if ctx != nil {
		object.Request.SetHeaders["X-Context-Provided"] = "true"
	}
	
	return object, nil
}

func (d *ModernDispatcher) DispatchEvent(eventJSON []byte)                                      {}
func (d *ModernDispatcher) DispatchObject(object *coprocess.Object) (*coprocess.Object, error) { return d.Dispatch(object) }
func (d *ModernDispatcher) LoadModules()                                                        {}
func (d *ModernDispatcher) HandleMiddlewareCache(b *apidef.BundleManifest, basePath string)    {}
func (d *ModernDispatcher) Reload()                                                             {}

// TestLegacyDispatcherBackwardCompatibility verifies old dispatchers still work
func TestLegacyDispatcherBackwardCompatibility(t *testing.T) {
	dispatcher := &LegacyDispatcher{}
	
	object := &coprocess.Object{
		HookName: "test_hook",
		HookType: coprocess.HookType_Pre,
		Request: &coprocess.MiniRequestObject{
			Method: "GET",
			Url:    "/test",
		},
	}
	
	// Call Dispatch (old method)
	result, err := dispatcher.Dispatch(object)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}
	
	if !dispatcher.dispatchCalled {
		t.Error("Dispatch should have been called")
	}
	
	if result.Request.SetHeaders["X-Legacy-Processed"] != "true" {
		t.Error("Legacy dispatcher should have processed the request")
	}
}

// TestLegacyDispatcherFallback verifies that code handles legacy dispatchers
// that don't implement DispatcherWithContext
func TestLegacyDispatcherFallback(t *testing.T) {
	dispatcher := &LegacyDispatcher{}
	
	object := &coprocess.Object{
		Request: &coprocess.MiniRequestObject{
			Method: "GET",
			Url:    "/test",
		},
	}
	
	// Verify legacy dispatcher only implements base Dispatcher interface
	var _ coprocess.Dispatcher = dispatcher
	
	// Type assertion should fail for DispatcherWithContext
	if _, ok := interface{}(dispatcher).(coprocess.DispatcherWithContext); ok {
		t.Error("Legacy dispatcher should not implement DispatcherWithContext")
	}
	
	// But regular Dispatch should work
	result, err := dispatcher.Dispatch(object)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}
	
	if !dispatcher.dispatchCalled {
		t.Error("Dispatch should have been called")
	}
	
	if result.Request.SetHeaders["X-Legacy-Processed"] != "true" {
		t.Error("Legacy dispatcher should have processed the request")
	}
}

// TestModernDispatcherWithBothMethods verifies modern dispatchers work with both methods
func TestModernDispatcherWithBothMethods(t *testing.T) {
	dispatcher := &ModernDispatcher{}
	
	object := &coprocess.Object{
		Request: &coprocess.MiniRequestObject{
			Method: "GET",
			Url:    "/test",
		},
	}
	
	// Test Dispatch (should delegate to DispatchWithContext)
	result, err := dispatcher.Dispatch(object)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}
	
	if !dispatcher.dispatchCalled {
		t.Error("Dispatch should have been called")
	}
	
	if !dispatcher.dispatchWithContextCalled {
		t.Error("DispatchWithContext should have been called internally")
	}
	
	if result.Request.SetHeaders["X-Modern-Processed"] != "true" {
		t.Error("Modern dispatcher should have processed the request")
	}
	
	if result.Request.SetHeaders["X-Context-Provided"] != "true" {
		t.Error("Context should have been provided (even if Background)")
	}
}

// TestModernDispatcherDirectContextCall verifies DispatchWithContext works directly
func TestModernDispatcherDirectContextCall(t *testing.T) {
	dispatcher := &ModernDispatcher{} // Reset flags
	
	object := &coprocess.Object{
		Request: &coprocess.MiniRequestObject{
			Method: "GET",
			Url:    "/test",
		},
	}
	
	// Call DispatchWithContext directly
	ctx := context.WithValue(context.Background(), "test_key", "test_value")
	result, err := dispatcher.DispatchWithContext(ctx, object)
	if err != nil {
		t.Fatalf("DispatchWithContext failed: %v", err)
	}
	
	if !dispatcher.dispatchWithContextCalled {
		t.Error("DispatchWithContext should have been called")
	}
	
	if result.Request.SetHeaders["X-Modern-Processed"] != "true" {
		t.Error("Modern dispatcher should have processed the request")
	}
	
	if result.Request.SetHeaders["X-Context-Provided"] != "true" {
		t.Error("Context should have been provided")
	}
}

// TestBuiltInDispatchersCompileTimeCheck verifies interface implementation at compile time
func TestBuiltInDispatchersCompileTimeCheck(t *testing.T) {
	// This test verifies dispatcher interface compliance
	// The actual GRPCDispatcher is in the gateway package and is tested there
	// This just verifies our test dispatchers satisfy the interface
	var _ coprocess.Dispatcher = &LegacyDispatcher{}
	var _ coprocess.Dispatcher = &ModernDispatcher{}
	var _ coprocess.DispatcherWithContext = &ModernDispatcher{}
	
	t.Log("All dispatcher implementations satisfy their respective interfaces")
}

// TestDispatcherInterfaceCompleteness ensures all methods are implemented
func TestDispatcherInterfaceCompleteness(t *testing.T) {
	// Test that legacy dispatcher only implements base Dispatcher
	var _ coprocess.Dispatcher = &LegacyDispatcher{}
	
	// Test that modern dispatcher implements DispatcherWithContext (which embeds Dispatcher)
	var _ coprocess.DispatcherWithContext = &ModernDispatcher{}
	
	// If this compiles, interface completeness is verified
	t.Log("Interface completeness verified")
}

// TestNilContextHandling verifies nil context is handled gracefully
func TestNilContextHandling(t *testing.T) {
	dispatcher := &ModernDispatcher{}
	
	object := &coprocess.Object{
		Request: &coprocess.MiniRequestObject{
			Method: "GET",
			Url:    "/test",
		},
	}
	
	// Call with nil context (should not panic)
	result, err := dispatcher.DispatchWithContext(nil, object)
	if err != nil {
		t.Fatalf("DispatchWithContext with nil context failed: %v", err)
	}
	
	if result == nil {
		t.Fatal("Result should not be nil")
	}
	
	// Should still process successfully
	if result.Request.SetHeaders["X-Modern-Processed"] != "true" {
		t.Error("Should process even with nil context")
	}
}
