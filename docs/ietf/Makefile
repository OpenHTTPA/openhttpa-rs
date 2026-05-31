.PHONY: all html txt xml pdf validate build-image clean-image

# Bash is required for the process-substitution used to filter the benign
# "*** sections left [nil]!" diagnostic emitted by kramdown-rfc2629.
SHELL      := /bin/bash

DOCKER_IMAGE := openhttpa-rfc-builder
DOCKERFILE   := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))Dockerfile.rfc
# Sentinel file: touched whenever the image is freshly built.  Make uses its
# mtime to decide whether a rebuild is needed (i.e. if Dockerfile.rfc is newer
# than the stamp, the image is rebuilt automatically).
IMAGE_STAMP  := .docker-image-stamp

DOCKER_CMD := docker run --rm --user $$(id -u):$$(id -g) \
              -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
              -e KRAMDOWN_DONT_FETCH_REFS=1 \
              -v $$(pwd):/workspace \
              $(DOCKER_IMAGE)
DRAFT      := draft-openhttpa-protocol-00

# /tmp is always writable by any user inside the container; avoids
# "Unable to find a suitable cache directory" warnings from xml2rfc.
XML2RFC    := xml2rfc --cache /tmp/xml2rfc-cache

all: xml html txt pdf validate

# ---------------------------------------------------------------------------
# Docker image – built automatically whenever Dockerfile.rfc changes.
# The stamp file acts as Make's proxy for the image's existence/freshness.
# ---------------------------------------------------------------------------
$(IMAGE_STAMP): $(DOCKERFILE)
	@echo "==> Building Docker image '$(DOCKER_IMAGE)' from $(DOCKERFILE) …"
	docker build -f $(DOCKERFILE) -t $(DOCKER_IMAGE) $(dir $(DOCKERFILE))
	@touch $(IMAGE_STAMP)

# Convenience alias
build-image: $(IMAGE_STAMP)

# Force-remove the image and stamp so the next make invocation rebuilds it.
clean-image:
	docker rmi -f $(DOCKER_IMAGE) 2>/dev/null || true
	@rm -f $(IMAGE_STAMP)

# ---------------------------------------------------------------------------
# Document targets – all depend on the image being present.
# ---------------------------------------------------------------------------
xml: $(IMAGE_STAMP)
	# Filter the benign "*** sections left [nil]!" diagnostic from kramdown-rfc2629.
	# It is printed to stderr whenever the tool auto-closes Markdown sections that
	# are not explicitly terminated (normal for RFC documents using --- back).
	# Process substitution keeps stdout → XML file and real errors → terminal.
	$(DOCKER_CMD) kramdown-rfc2629 -3 $(DRAFT).md \
		2> >(grep -v "^\*\*\* sections left" >&2) \
		> $(DRAFT).xml
	python3 xml2v3.py $(DRAFT).xml

html: xml
	$(DOCKER_CMD) $(XML2RFC) $(DRAFT).xml --html

txt: xml
	$(DOCKER_CMD) $(XML2RFC) $(DRAFT).xml --text

pdf: xml
	$(DOCKER_CMD) $(XML2RFC) $(DRAFT).xml --pdf

validate: xml
	$(DOCKER_CMD) idnits --mode submission --output simple $(DRAFT).xml

clean:
	rm -f $(DRAFT).xml $(DRAFT).html $(DRAFT).txt $(DRAFT).pdf
