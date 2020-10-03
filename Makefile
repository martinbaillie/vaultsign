SHELL 		:=$(shell which bash)
.SHELLFLAGS =-c

ifndef DEBUG
.SILENT: ;
endif
.EXPORT_ALL_VARIABLES: ;

WORKDIR 	=$(patsubst %/,%,$(dir $(realpath $(lastword $(MAKEFILE_LIST)))))
PROJECT 	=$(notdir $(WORKDIR))
REVISION 	=$(shell git rev-parse --verify --short HEAD)
VERSION 	=$(shell git describe --always --tags --exact-match 2>/dev/null || \
				echo $(REVISION))

GPG_KEY 	?=$(shell git config user.signingkey)
GPG			=$(shell command -v gpg || (apt-get -qq update &>/dev/null && \
				apt-get -yqq install gpg &>/dev/null && \
				command -v gpg))

target/debug/$(PROJECT): ; cargo build
target/release/$(PROJECT): ; cargo build --release

build: target/debug/$(PROJECT)
release: target/release/$(PROJECT)
acceptance: target/release/$(PROJECT); ./hack/acceptance_test.bash
.PHONY: build release acceptance

tag:
	echo >&2 "==> Tagging"
	if [[ ! $(VERSION) =~ ^[0-9]+[.][0-9]+([.][0.9]*)?$  ]]; then \
		echo >&2 "ERROR: VERSION ($(VERSION)) is not a semantic version"; \
		exit 1; \
	fi
	if ! grep "version = \"$(VERSION)\"" Cargo.toml; then \
		echo >&2 "ERROR: VERSION ($(VERSION)) not found in Cargo.toml"; \
		exit 1; \
	fi
	git tag \
		--annotate \
		--create-reflog \
		--local-user "$(GPG_KEY)" \
		--message "Version $(VERSION)" \
		--sign \
		"v$(VERSION)" master
.PHONY: tag

SHA256SUMS:
	echo >&2 "==> Summing"
	shasum --algorithm 256 $(PROJECT)-* > $@

SHA256SUMS.sig: SHA256SUMS
	echo >&2 "==> Signing"
	$(GPG) --default-key "$(GPG_KEY)" --detach-sig SHA256SUMS
