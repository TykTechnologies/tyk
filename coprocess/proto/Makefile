.PHONY: all

# We need to access `..` to write out files
parentDir := $(shell realpath -s ..)

all:
	docker build --rm -t internal/coprocess-proto-env --squash .
	docker run -it --rm -w $(PWD) -v $(parentDir):$(parentDir) internal/coprocess-proto-env ./update_bindings.sh
