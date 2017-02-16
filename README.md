# certigo

[![license](http://img.shields.io/badge/license-apache_2.0-blue.svg?style=flat)](https://raw.githubusercontent.com/square/certigo/master/LICENSE)
[![release](https://img.shields.io/github/release/square/certigo.svg?style=flat)](https://github.com/square/certigo/releases)
[![build](https://travis-ci.org/square/certigo.svg?branch=master)](https://travis-ci.org/square/certigo)
[![report](https://goreportcard.com/badge/github.com/square/certigo)](https://goreportcard.com/report/github.com/square/certigo)

Certigo is a utility to examine and validate certificates to help with debugging SSL/TLS issues.

### Features

**Supports all common file formats**: Certigo can read and dump certificates in various formats. It can automatically detect and read from X.509 (DER/PEM), JCEKS/JKS, PKCS7 and PKCS12 files. Certificates can be dumped to a human-readable format, a set of PEM blocks, or a JSON object for use in scripting. 

**Validation and linting**: Not sure if your generated certificate is valid? Certigo can connect to remote servers to display and validate their certificate chains. It can also point out common errors on certififcates, such as using an older X.509 format, signatures with outdated hashes, or keys that are too small. 

**Supports MySQL and PostgreSQL**: Trying to debug SSL/TLS connections on a database? Certigo supports establishing connections via StartTLS protocols for MySQL and PostgreSQL, making it possible debug connection issues or scan for expired certificates more easily.

**Scripting support**: All commands in certigo have support for optional JSON output, which can be used in shell scripts to analyze or filter output. Combine certigo with [jq](https://stedolan.github.io/jq) to find all certificates in a bundle that are signed with SHA1-RSA, or filter for CA certificates, or whatever you need!

### Install

To install certigo, simply use:

    go get -u github.com/square/certigo

On macOS you can also use homebrew to install:

    brew install certigo

Note that certigo requires Go 1.5 or later to build.

### Develop

We use [glide][1] for managing vendored dependencies.

[1]: https://glide.sh

### Usage

Certigo can read certificates/keystores in various formats and dump them to stdout.

Certigo will display information in a human-readable way, and print warnings for common mistakes (such as small key sizes or weak signatures/hash functions). Certigo can also convert any input to a series of PEM blocks, which is useful if you want to e.g. dump the contents of unusual container formats into something more useful.

```
usage: certigo [<flags>] <command> [<args> ...]

A command line certificate examination utility.

Flags:
  --help     Show context-sensitive help (also try --help-long and --help-man).
  --version  Show application version.

Commands:
  help [<command>...]
    Show help.

  dump [<flags>] [<file>...]
    Display information about a certificate from a file/stdin.

  connect [<flags>] [<server:port>]
    Connect to a server and print its certificate(s).

  verify --name=NAME [<flags>] [<file>]
    Verify a certificate chain from file/stdin against a name.
```

### Examples

Display information about a certificate (from a file, or from stdin):

<img src="https://cdn.rawgit.com/square/certigo/0a355c64b7200e9fda65b68f6fb81730b3b7d341/examples/example_1.svg" width="100%" height="100%">

Export certificates/keys from a keystore into PEM blocks:

<img src="https://cdn.rawgit.com/square/certigo/0a355c64b7200e9fda65b68f6fb81730b3b7d341/examples/example_2.svg" width="100%" height="100%">

Display information about a certificate from a remote server:

<img src="https://cdn.rawgit.com/square/certigo/0a355c64b7200e9fda65b68f6fb81730b3b7d341/examples/example_3.svg" width="100%" height="100%">
