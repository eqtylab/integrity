.PHONY: default
default: all


# To generate all static context files run:
#
#   make
#
# Note: CID env vars are set by nix shell


http-urls := \
www.w3.org/2018/credentials/v1 \
www.w3.org/ns/credentials/v2 \
www.w3.org/ns/did/v1 \
w3id.org/security/v1 \
w3id.org/security/v2

dirs := http cid

http-targets := $(addprefix http/,${http-urls})
cid-targets := $(addprefix cid/,${cids})

.PHONY: all
all: ${http-targets} ig-context

${http-targets}: http/%: http
	mkdir -p $(dir $@)
	curl -s -L -o http/$* http://$*

${dirs}:
	mkdir -p $@

.PHONY: clean
clean:
	rm -rf ${dirs}
