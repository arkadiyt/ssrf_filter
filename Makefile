build:
	docker build --tag ssrf_filter .

bash: build
	docker run --rm -it ssrf_filter

console: build
	docker run --rm -it ssrf_filter irb -r 'bundler/setup' -r 'ssrf_filter'

%: build
	docker run --rm -it ssrf_filter make -f Makefile.docker $@
