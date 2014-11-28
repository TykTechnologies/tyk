build/container: stage/tyk Dockerfile
	docker build --no-cache -t tyk .
	touch build/container

build/tyk: *.go
	GOOS=linux GOARCH=amd64 go build -o build/tyk

stage/tyk: build/tyk
	mkdir -p stage
	cp build/tyk stage/tyk

release:
	docker tag tyk lonelycode/tyk
	docker push lonelycode/tyk

.PHONY: clean
clean:
	rm -rf build
