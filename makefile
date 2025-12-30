all:
	docker compose build

lint:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run
gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@latest ./...
test:
	go test 

run:
	docker compose stop
	docker compose build
	docker compose up

rdp:
	xfreerdp /gt:https  /gateway-usage-method:direct  /v:testuser_test-vm /gu:testuser /gp:dogood  /g:localhost:8443   /u:testuser   /p:testpassword   /cert:ignore /gt:https  

