VERSION = $(shell cargo read-manifest | jq -r .version)
DEST = output/v$(VERSION)

all: $(DEST) tar rpm deb

$(DEST):
	mkdir -p $(DEST)

.PHONY: tar
tar: $(DEST)
	scripts/package-tar.sh $(DEST)/edgebit-agent-$(VERSION).x86_64.tar.gz

.PHONY: rpm
rpm: $(DEST)
	VERSION=$(VERSION) nfpm package --packager rpm --target $(DEST)

.PHONY: deb
deb: $(DEST)
	VERSION=$(VERSION) nfpm package --packager deb --target $(DEST)
