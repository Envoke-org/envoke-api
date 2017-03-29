#!/bin/sh

source init.sh

read -p "Enter directory for user credentials: " directory

read -p "Enter path to audio file: " path

export DIR=$directory
export PATH_TO_AUDIO_FILE=$path

cd ~/go/src/github.com/zbo14/envoke/crypto
go test -v

cd ~/go/src/github.com/zbo14/envoke/bigchain 
go test -v

cd ~/go/src/github.com/zbo14/envoke/api
go test -v