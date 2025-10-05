SERVICE_NAME := sso

build:
	@env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/${SERVICE_NAME} cmd/main.go