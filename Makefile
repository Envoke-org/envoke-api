# From https://developer.atlassian.com/blog/2015/07/osx-static-golang-binaries-with-docker/

default: build-static

build-dynamic:
	docker build -t build-api -f Dockerfile.build_ .
	docker run --rm build-api | docker build --build-arg endpoint=http://<host:port>/api/v1/ -t envoke-api -f Dockerfile.run -

build-static:
	docker build -t build-api -f Dockerfile.build .
	docker run -t build-api /bin/true
	docker cp `docker ps -q -n=1`:/main .
	chmod 755 ./main
	docker build --build-arg endpoint=http://<host:port>/api/v1/ --rm=true --tag=envoke-api -f Dockerfile.static .

run-dynamic: 
	build-dynamic	
	docker run -p 8888:8888 envoke-api

run-static: 
	build-static
	docker run -p 8888:8888 envoke-api