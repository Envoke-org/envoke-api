#!/bin/sh

source init.sh

cd ~/go/src/github.com/Envoke-org/envoke-api
rm envoke-api
go build 
./envoke-api