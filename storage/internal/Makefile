.PHONY: all

all:
	go fmt ./...
	cp redis6/driver.go redis7/driver.go
	go test -tags=integration -v -race -coverprofile=coverage.out -cover -coverpkg=./... ./...
	go tool cover -html=coverage.out