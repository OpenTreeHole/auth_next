# Open Tree Hole Auth Next

Next Generation of Auth microservice integrated with [kong](https://github.com/Kong/kong) for registration and issuing tokens

## Features

- White-listed email registration
- Anonymous: RSA encrypted personal information(email) and random identity
- issue and revoke JWT tokens

## Usage

### build and run

```shell
git clone https://github.com/OpenTreeHole/auth_next.git
cd auth_next
# install swag and generate docs
go install github.com/swaggo/swag/cmd/swag@latest
swag init --parseInternal --parseDepth 1 # to generate the latest docs, this should be run before compiling
# build for debug
go build -o auth.exe
# build for release
go build -tags "release" -ldflags "-s -w" -o auth.exe
# run
./auth.exe
```

### test

```shell
export MODE=test
go test -v ./tests/...
```

### benchmark

```shell
export MODE=bench
go test -v -benchmem -cpuprofile=cpu.out -benchtime=1s ./benchmarks/... -bench .
```
For documentation, please open http://localhost:8000/docs after running app
## Badge

[![stars](https://img.shields.io/github/stars/OpenTreeHole/auth_next)](https://github.com/OpenTreeHole/auth_next/stargazers)
[![issues](https://img.shields.io/github/issues/OpenTreeHole/auth_next)](https://github.com/OpenTreeHole/auth_next/issues)
[![pull requests](https://img.shields.io/github/issues-pr/OpenTreeHole/auth_next)](https://github.com/OpenTreeHole/auth_next/pulls)

[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

### Powered by

![Go](https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white)
![Swagger](https://img.shields.io/badge/-Swagger-%23Clojure?style=for-the-badge&logo=swagger&logoColor=white)

## Contributing

Feel free to dive in! [Open an issue](https://github.com/OpenTreeHole/auth_next/issues/new) or [Submit PRs](https://github.com/OpenTreeHole/auth_next/compare).

We are now in rapid development, any contribution would be of great help.

### Contributors

This project exists thanks to all the people who contribute.

<a href="https://github.com/OpenTreeHole/auth_next/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=OpenTreeHole/auth_next"  alt="contributors"/>
</a>

## Licence

[![license](https://img.shields.io/github/license/OpenTreeHole/auth_next)](https://github.com/OpenTreeHole/auth_next/blob/master/LICENSE)
© OpenTreeHole
