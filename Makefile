.PHONY: gen build run

gen:
	go generate ./...

build:
	go build -o netagent ./cmd/netagent

run: build
	sudo ./netagent -config config.yaml
