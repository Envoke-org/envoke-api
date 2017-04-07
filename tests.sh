#!/bin/sh

source init.sh

cd ~/go/src/github.com/Envoke-org/envoke-api/crypto
go test -v

cd ~/go/src/github.com/Envoke-org/envoke-api/bigchain 
go test -v

cd ~/go/src/github.com/Envoke-org/envoke-api/api
go test -v