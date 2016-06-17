# certigo

[![license](http://img.shields.io/badge/license-apache_2.0-blue.svg?style=flat)](https://raw.githubusercontent.com/square/certigo/master/LICENSE)
[![build](https://travis-ci.org/square/certigo.svg?branch=master)](https://travis-ci.org/square/certigo)
[![report](https://goreportcard.com/badge/github.com/square/certigo)](https://goreportcard.com/report/github.com/square/certigo)

Certigo is a utility to examine and validate certificates in a variety of formats.

### Install

To install certigo, simply use:

    go get -u github.com/square/certigo

Note that certigo requires Go 1.6 or later to build.

### Develop

We use [glide][1] for managing vendored dependencies.

[1]: https://glide.sh

### Usage

Certigo can read certificates/keystores in various formats and dump them to stdout.

Currently supported formats are DER, PEM, JCEKS and PKCS12. It's a one-stop shop for debugging/analyzing certs.

For example (from stdin):

<img src="https://cdn.rawgit.com/square/certigo/svg/examples/example_1_245953.svg" width="100%" height="100%">

Or from a file:

<img src="https://cdn.rawgit.com/square/certigo/svg/examples/example_2_d848d5.svg" width="100%" height="100%">

You can dump a cert chain from a TLS server. Unlike `openssl x509 -text`, certigo will dump the entire chain, not just the first certificate:

<img src="https://cdn.rawgit.com/square/certigo/svg/examples/example_3_ffafad.svg" width="100%" height="100%">
