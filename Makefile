APP:=$(notdir $(CURDIR))
GOPATH:=$(shell go env GOPATH)

GOHOSTOS:=$(shell go env GOHOSTOS)
GOHOSTARCH:=$(shell go env GOHOSTARCH)

GIT_COMMIT_SHA:=$(shell git rev-parse --short=12 HEAD 2>/dev/null)
GIT_REMOTE_URL:=$(shell git config --get remote.origin.url 2>/dev/null)
GIT_COMMIT_DATE:=$(shell TZ=UTC git show -s --date=format:'%Y%m%d%H%M%S' --pretty='format:%cd' HEAD)
VERSION:=0.0.0+$(GIT_COMMIT_DATE).$(GIT_COMMIT_SHA)
SHASUM_CHECK:=$(shell shasum --version >/dev/null 2>&1 && echo shasum -a 256 -c || echo sha256sum -c)
SHELL:=/bin/bash
ifneq ($(strip $(V)),)
	override V := -v
endif

.PHONY: all deps bootstrap test coverage vet build parallelise
all: build

export GO111MODULE=on
export GOPRIVATE=*.ibm.com

ARCHIVE_EXTENSION:=.tar.gz
BINARY_EXTENSION:=
EXTRACT_COMMAND:=tar --to-stdout -zxf
# golangci-lint
# https://github.com/golangci/golangci-lint/releases/tag/v1.41.1
GOLANGCI_LINT_VERSION:=1.41.1
ifeq (${GOHOSTOS},linux)
ifeq (${GOHOSTARCH},s390x)
GOLANGCI_LINT_SHA256:=63b52d026b6d55e52402faabfcf0fcbfe5ced2dd50e91439f8414aa558dbb093
else ifeq (${GOHOSTARCH},pp64le)
GOLANGCI_LINT_SHA256:=fba455f5b71d28e494bd2554482b3583823e48c9dfc3c81ce8c0ec3079d6609f
else
GOLANGCI_LINT_SHA256:=23e1078ab00a750afcde7e7eb5aab8e908ef18bee5486eeaa2d52ee57d178580
endif
else ifeq (${GOHOSTOS},darwin)
GOLANGCI_LINT_SHA256:=904a2100b073f67cfc0d9bee48aa75fcf170e3027ca475b1f050af4acc19fcad
else
GOLANGCI_LINT_SHA256:=
ARCHIVE_EXTENSION:=.zip
BINARY_EXTENSION:=.exe
EXTRACT_COMMAND:=unzip -p
endif
#

${GOPATH}/bin/golangci-lint-${GOLANGCI_LINT_VERSION}${BINARY_EXTENSION}:
	mkdir -p ${GOPATH}/bin
	wget -qO golangci-lint${ARCHIVE_EXTENSION} https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_LINT_VERSION}/golangci-lint-${GOLANGCI_LINT_VERSION}-${GOHOSTOS}-${GOHOSTARCH}${ARCHIVE_EXTENSION}
	@echo "${GOLANGCI_LINT_SHA256}  golangci-lint${ARCHIVE_EXTENSION}" | ${SHASUM_CHECK} -
	${EXTRACT_COMMAND} golangci-lint${ARCHIVE_EXTENSION} golangci-lint-${GOLANGCI_LINT_VERSION}-${GOHOSTOS}-${GOHOSTARCH}/golangci-lint${BINARY_EXTENSION} >$@
	@chmod 700 $@
	@$@ --version
	@rm -f golangci-lint${ARCHIVE_EXTENSION}

deps:
	grep -oE '^\s+github.ibm.com/mhub/[^ ]+' go.mod | xargs go get
	-go mod tidy

bootstrap:
	cd "$$(mktemp -d)" && \
		go get github.ibm.com/mhub/mhub-bootstrap && \
	${GOPATH}/bin/mhub-bootstrap
	$(MAKE) deps

build:
ifneq (${GOHOSTOS},linux)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ${APP}-linux-amd64 -ldflags "-s -w -X \"main.Version=$(VERSION)\" ${LDFLAGS}" -a -trimpath .
endif
	CGO_ENABLED=0 go build -o ${APP}-${GOHOSTOS}-${GOHOSTARCH} -ldflags "-s -w -X \"main.Version=$(VERSION)\" ${LDFLAGS}" -a -trimpath .

${GOPATH}/bin/parallelise:
	cd "$$(mktemp -d)" && go get github.ibm.com/dominic-evans/parallelise

parallelise: ${GOPATH}/bin/parallelise
	@FILES=$$(find . -name '*_test.go' -print); \
	if [ -n "$${FILES}" ] && [ -n "$$($< -l $${FILES})" ]; then \
	  echo 'Error: not all test functions contain a t.Parallel() call.' >&2; \
	  echo 'Please run "make parallelisefix" or run "parallelise -w" on all of your "_test.go" files.' >&2; \
	  exit 1; \
	fi

parallelisefix: ${GOPATH}/bin/parallelise
	@FILES=$$(find . -name '*_test.go' -print); \
	if [ -n "$${FILES}" ]; then \
	  $< -w $${FILES}; \
	fi

vet: ${GOPATH}/bin/golangci-lint-${GOLANGCI_LINT_VERSION}${BINARY_EXTENSION} parallelise
	$< run $(V) ./...
	${GOPATH}/bin/helm-chart-static-analyzer

vetfix: ${GOPATH}/bin/golangci-lint-${GOLANGCI_LINT_VERSION}${BINARY_EXTENSION}
	@echo Applying available automatic fixes for vet warnings...
	$< run --fix ./...
