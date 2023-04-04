export VERSION = $(shell cargo read-manifest | jq -r .version)
DEST = output/
SYFT_RELEASE = 0.74.1
export ARCH = $(shell uname -m)
export GOARCH = $(shell uname -m | sed -e "s/x86_64/amd64/" -e "s/aarch64/arm64/")

all: $(DEST) tar rpm deb

$(DEST):
	mkdir -p $(DEST)

.PHONY: syft
syft:
	mkdir -p syft
	rm -rf syft/*
	cd syft && curl -fsSL https://github.com/anchore/syft/releases/download/v$(SYFT_RELEASE)/syft_$(SYFT_RELEASE)_linux_$(GOARCH).tar.gz | tar xz

.PHONY: tar
tar: $(DEST) syft
	scripts/package-tar.sh $(DEST)/edgebit-agent-$(VERSION).$(ARCH).tar.gz

.PHONY: rpm
rpm: $(DEST) syft
	nfpm package --packager rpm --target $(DEST)

.PHONY: deb
deb: $(DEST) syft
	nfpm package --packager deb --target $(DEST)
