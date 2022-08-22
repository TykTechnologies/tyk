.PHONY: all

all:
	go fmt ./...
	cp redis6/driver.go redis7/driver.go
	go test -tags=e2e -v -race -coverprofile=coverage.out -coverpkg=github.com/TykTechnologies/tyk/storage/internal,github.com/TykTechnologies/tyk/storage/internal/model,github.com/TykTechnologies/tyk/storage/internal/redis6,github.com/TykTechnologies/tyk/storage/internal/redis7 ./...
	go tool cover -html=coverage.out