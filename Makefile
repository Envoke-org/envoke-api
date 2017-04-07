default: build

build:
	docker build --build-arg endpoint=http://192.168.99.100:59984/api/v1/ -t build-api -f Dockerfile.build .
	docker run -t build-api /bin/true
	docker cp `docker ps -q -n=1`:/main .
	chmod 755 ./main
	docker build --rm=true --tag=envoke-api -f Dockerfile.static .

run: build
	docker run -p 8888:8888 envoke-api


