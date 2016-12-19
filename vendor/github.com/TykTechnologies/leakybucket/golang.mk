# This is the default Clever Golang Makefile.
# Please do not alter this file directly.
GOLANG_MK_VERSION := 0.1.0

SHELL := /bin/bash
.PHONY: golang-godep-vendor golang-test-deps $(GODEP)

# This block checks and confirms that the proper Go toolchain version is installed.
# arg1: golang version
define golang-version-check
GOVERSION := $(shell go version | grep $(1))
_ := $(if \
	$(shell go version | grep $(1)), \
	@echo "", \
	$(error "must be running Go version $(1)"))
endef

export GO15VENDOREXPERIMENT=1

# FGT is a utility that exits with 1 whenever any stderr/stdout output is recieved.
FGT := $(GOPATH)/bin/fgt
$(FGT):
	go get github.com/GeertJohan/fgt

# Godep is a tool used to manage Golang dependencies in the style of the Go 1.5
# vendoring experiment.
GODEP := $(GOPATH)/bin/godep
$(GODEP):
	go get -u github.com/tools/godep

# Golint is a tool for linting Golang code for common errors.
GOLINT := $(GOPATH)/bin/golint
$(GOLINT):
	go get github.com/golang/lint/golint

# golang-vendor-deps installs all dependencies needed for different test cases.
golang-godep-vendor-deps: $(GODEP)

# golang-godep-vendor is a target for saving dependencies with the godep tool
# to the vendor/ directory. All nested vendor/ directories are deleted as they
# are not handled well by the Go toolchain.
# arg1: pkg path
define golang-godep-vendor
$(GODEP) save $(1)
@# remove any nested vendor directories
find vendor/ -path '*/vendor' -type d | xargs -IX rm -r X
endef

# golang-fmt-deps requires the FGT tool for checking output
golang-fmt-deps: $(FGT)

# golang-fmt checks that all golang files in the pkg are formatted correctly.
# arg1: pkg path
define golang-fmt
@echo "FORMATTING $(1)..."
@$(FGT) gofmt -l=true $(GOPATH)/src/$(1)/*.go
endef

# golang-lint-deps requires the golint tool for golang linting.
golang-lint-deps: $(GOLINT)

# golang-lint calls golint on all golang files in the pkg.
# arg1: pkg path
define golang-lint
@echo "LINTING $(1)..."
@$(GOLINT) $(GOPATH)/src/$(1)/*.go
endef

# golang-lint-deps-strict requires the golint tool for golang linting.
golang-lint-deps-strict: $(GOLINT) $(FGT)

# golang-lint-strict calls golint on all golang files in the pkg and fails if any lint
# errors are found.
# arg1: pkg path
define golang-lint-strict
@echo "LINTING $(1)..."
@$(FGT) $(GOLINT) $(GOPATH)/src/$(1)/*.go
endef

# golang-test-deps is here for consistency
golang-test-deps:

# golang-test uses the Go toolchain to run all tests in the pkg.
# arg1: pkg path
define golang-test
@echo "TESTING $(1)..."
@go test -v $(1)
endef

# golang-test-strict-deps is here for consistency
golang-test-strict-deps:

# golang-test-strict uses the Go toolchain to run all tests in the pkg with the race flag
# arg1: pkg path
define golang-test-strict
@echo "TESTING $(1)..."
@go test -v -race $(1)
endef

# golang-vet-deps is here for consistency
golang-vet-deps:

# golang-vet uses the Go toolchain to vet all the pkg for common mistakes.
# arg1: pkg path
define golang-vet
@echo "VETTING $(1)..."
@go vet $(GOPATH)/src/$(1)/*.go
endef

# golang-test-all-deps installs all dependencies needed for different test cases.
golang-test-all-deps: golang-fmt-deps golang-lint-deps golang-test-deps golang-vet-deps

# golang-test-all calls fmt, lint, vet and test on the specified pkg.
# arg1: pkg path
define golang-test-all
$(call golang-fmt,$(1))
$(call golang-lint,$(1))
$(call golang-vet,$(1))
$(call golang-test,$(1))
endef

# golang-test-all-strict-deps: installs all dependencies needed for different test cases.
golang-test-all-strict-deps: golang-fmt-deps golang-lint-deps-strict golang-test-strict-deps golang-vet-deps

# golang-test-all-strict calls fmt, lint, vet and test on the specified pkg with strict
# requirements that no errors are thrown while linting.
# arg1: pkg path
define golang-test-all-strict
$(call golang-fmt,$(1))
$(call golang-lint-strict,$(1))
$(call golang-vet,$(1))
$(call golang-test-strict,$(1))
endef
