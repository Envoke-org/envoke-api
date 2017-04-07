FROM golang:1.7.1

ARG endpoint
ENV ENDPOINT $endpoint

RUN go get github.com/Envoke-org/envoke-api
WORKDIR /go/src/github.com/Envoke-org/envoke-api
RUN go build

CMD envoke-api

EXPOSE 8888