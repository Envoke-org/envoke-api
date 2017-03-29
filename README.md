## envoke-cli

A demo client-side application for persisting, querying, and validating music metadata in BigchainDB/IPDB.

### Install 

Download and install [Go](https://golang.org/dl/).

In a terminal window, `go get github.com/Envoke-org/envoke-cli/cmd/envoke`

### Usage

In a terminal window, `cd ~/go/src/github.com/Envoke-org/envoke-cli`...

* **Demo app**
	
	`sh start_app.sh` 

	You will be prompted to enter an endpoint to the BigchainDB/IPDB http-api. 

	In your browser, go to `http://localhost:8888/<endpoint>`

*  **Run tests**

	`sh run_tests.sh`

	You will be prompted to enter...
	
		- a path to a directory for user credentials
		- an endpoint to the BigchainDB/IPDB http-api
		- a path to an audio file
