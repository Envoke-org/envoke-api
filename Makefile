# From https://developer.atlassian.com/blog/2015/07/osx-static-golang-binaries-with-docker/

default: build-static

build-dynamic:
	docker build --build-arg endpoint=http://192.168.99.100:59984/api/v1/ -t build-api -f Dockerfile.build_ .
	docker run --rm build-api | docker build -t envoke-api -f Dockerfile.run -

build-static:
	docker build --build-arg endpoint=http://192.168.99.100:59984/api/v1/ -t build-api -f Dockerfile.build .
	docker run -t build-api /bin/true
	docker cp `docker ps -q -n=1`:/main .
	chmod 755 ./main
	docker build --rm=true --tag=envoke-api -f Dockerfile.static .

run: docker run -p 8888:8888 envoke-api

run-dynamic: build-dynamic	
	run

run-static: build-static
	run