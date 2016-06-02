# certigo

[![license](http://img.shields.io/badge/license-apache_2.0-red.svg?style=flat)](https://raw.githubusercontent.com/square/certigo/master/LICENSE)
[![build](https://travis-ci.org/square/certigo.svg?branch=master)](https://travis-ci.org/square/certigo)
[![report](https://goreportcard.com/badge/github.com/square/certigo)](https://goreportcard.com/report/github.com/square/certigo)

Certigo is a utility to examine and validate certificates in a variety of formats.

### Build

We use [glide](https://glide.sh) for vendoring.
Use `go get github.com/Masterminds/glide` or `brew install glide` (on OS X) to install it.

Then, to pull in dependencies and build certigo:

    make depends build

Certigo is tested with Go 1.6.
