# From https://developer.atlassian.com/blog/2015/07/osx-static-golang-binaries-with-docker/

default: build

build:
	docker build --build-arg endpoint=http://<host:port>/api/v1/ -t build-api -f Dockerfile.build .
	docker run -t build-api /bin/true
	docker cp `docker ps -q -n=1`:/main .
	chmod 755 ./main
	docker build --rm=true --tag=envoke-api -f Dockerfile.static .

run: build
	docker run -p 8888:8888 envoke-api


