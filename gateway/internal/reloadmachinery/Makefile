.PHONY: all

all:
	go fmt ./...
	go test -cover -coverpkg=./... -coverprofile=c.out -count=1 -v .
	go tool cover -html=c.out