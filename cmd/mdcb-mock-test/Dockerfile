FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o mdcb-mock-test ./cmd/mdcb-mock-test/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/mdcb-mock-test .
EXPOSE 9090
CMD ["./mdcb-mock-test"]
