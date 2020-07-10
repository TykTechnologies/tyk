TPC ?= $(shell git tag | tail -1)

docker-compose = GW_VERSION=$(TPC) docker-compose -f plugins.yml -p tpc

.PHONY: check-header clean

check-header: plugin.so
	@curl -s -X POST http://localhost:8080/postplugin | jq -e 'if .headers.Foo != "Bar" then false else true end'
	@echo Found header Foo=Bar 

plugin.so:	foo-plugin.go plugins.yml
	docker run --rm -v $$PWD:/plugin-source tykio/tyk-plugin-compiler:$(TPC) $@
	cp $@ plugins/
	@echo Built plugin for $(TPC), bringing up compose env
	$(docker-compose) up --detach && sleep 2

clean:
	rm -fv *.so
	$(docker-compose) down
