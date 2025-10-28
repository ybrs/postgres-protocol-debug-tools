CARGO ?= cargo

.PHONY: all build-proxy build-inspector check fmt clean

all: build-proxy build-inspector

build-proxy:
	$(CARGO) build -p postgres-wire-proxy

build-inspector:
	$(CARGO) build -p pg-client-inspect

check:
	$(CARGO) check --all

fmt:
	$(CARGO) fmt

clean:
	$(CARGO) clean
