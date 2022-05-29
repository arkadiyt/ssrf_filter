build:
	docker build --tag ssrf_filter .

%:
	$(MAKE) build
	docker run --rm -v $${PWD}:/app -it ssrf_filter make -f Makefile.docker $@
