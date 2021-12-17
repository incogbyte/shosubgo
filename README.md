# shosubgo
Small tool to Grab subdomains using Shodan api.

## Get your shodan api FREE with limit usage:
<https://developer.shodan.io/api/requirements>

## Install

Until master is updated, this will not work.

```bash
$ go get github.com/incogbyte/shosubgo/apishodan
$ go build main.go
```

To build from source, now that Go does not support relative addressing:
- In main.go, change ./apishodan to apishodan in imports
- Move apishodan/api.go to the /usr/lib/go-<version>/src/ folder

```bash
$ go build main.go
```
Standard usage follows

## Usage
```bash
go run main.go -d target.com -s YourAPIKEY
```
## Usage download from releases:

https://github.com/incogbyte/shosubgo/releases/tag/1.1

```bash
# From Download Releases

./shosubgo_linux -d target.com -s YourAPIKEY
```

![shosubgo](https://raw.githubusercontent.com/incogbyte/shosubgo/master/shosubgo.png)


![gopher](https://encrypted-tbn0.gstatic.com/images?q=tbn%3AANd9GcTFcFPxQzLnq18PnHBkUxF6KfavmHX9q6Ukz-JWSNOg7iJu7Dsy)
