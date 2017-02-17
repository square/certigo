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

Display information about a certificate (also supports `--pem` and `--json` output):

```
$ certigo dump squareup-2016.crt
** CERTIFICATE 1 **
Serial: 260680855742043049380997676879525498489
Not Before: 2016-07-15 20:15:52 +0000 UTC
Not After : 2017-07-31 20:45:50 +0000 UTC
Signature : SHA256-RSA
Subject Info:
	Country: US
	Province: California
	Locality: San Francisco
	EV Incorporation Country: US
	EV Incorporation Province: Delaware
	Organization: Square, Inc.
	Business Category: Private Organization
	EV Incorporation Registration Number: 4699855
	CommonName: www.squareup.com
Issuer Info:
	Country: US
	Organization: Entrust, Inc.
	Organizational Unit: See www.entrust.net/legal-terms
	Organizational Unit: (c) 2014 Entrust, Inc. - for authorized use only
	CommonName: Entrust Certification Authority - L1M
Subject Key ID   : D4:17:14:6F:0B:C5:20:A1:D6:FE:21:7E:DC:9E:F8:57:9C:ED:AE:6A
Authority Key ID : C3:F7:D0:B5:2A:30:AD:AF:0D:91:21:70:39:54:DD:BC:89:70:C7:3A
Basic Constraints: CA:false
Key Usage:
	Digital Signature
	Key Encipherment
Extended Key Usage:
	Server Auth
	Client Auth
Alternate DNS Names:
	www.squareup.com
	squareup.com
	account.squareup.com
	mkt.com
	www.mkt.com
	market.squareup.com
	gosq.com
	www.gosq.com
	gosq.co
	www.gosq.co
```

Display & validate certificates from a remote server (also supports `--start-tls`):

```
$ certigo connect squareup.com:443
** CERTIFICATE 1 **
Serial: 260680855742043049380997676879525498489
Not Before: 2016-07-15 20:15:52 +0000 UTC
Not After : 2017-07-31 20:45:50 +0000 UTC
Signature : SHA256-RSA
Subject Info:
	Country: US
	Province: California
	Locality: San Francisco
	EV Incorporation Country: US
	EV Incorporation Province: Delaware
	Organization: Square, Inc.
	Business Category: Private Organization
	EV Incorporation Registration Number: 4699855
	CommonName: www.squareup.com
Issuer Info:
	Country: US
	Organization: Entrust, Inc.
	Organizational Unit: See www.entrust.net/legal-terms
	Organizational Unit: (c) 2014 Entrust, Inc. - for authorized use only
	CommonName: Entrust Certification Authority - L1M
Subject Key ID   : D4:17:14:6F:0B:C5:20:A1:D6:FE:21:7E:DC:9E:F8:57:9C:ED:AE:6A
Authority Key ID : C3:F7:D0:B5:2A:30:AD:AF:0D:91:21:70:39:54:DD:BC:89:70:C7:3A
Basic Constraints: CA:false
Key Usage:
	Digital Signature
	Key Encipherment
Extended Key Usage:
	Server Auth
	Client Auth
Alternate DNS Names:
	www.squareup.com
	squareup.com
	account.squareup.com
	mkt.com
	www.mkt.com
	market.squareup.com
	gosq.com
	www.gosq.com
	gosq.co
	www.gosq.co

** CERTIFICATE 2 **
Serial: 30215777750102225331854468774
Not Before: 2014-12-15 15:25:03 +0000 UTC
Not After : 2030-10-15 15:55:03 +0000 UTC
Signature : SHA256-RSA
Subject Info:
	Country: US
	Organization: Entrust, Inc.
	Organizational Unit: See www.entrust.net/legal-terms
	Organizational Unit: (c) 2014 Entrust, Inc. - for authorized use only
	CommonName: Entrust Certification Authority - L1M
Issuer Info:
	Country: US
	Organization: Entrust, Inc.
	Organizational Unit: See www.entrust.net/legal-terms
	Organizational Unit: (c) 2009 Entrust, Inc. - for authorized use only
	CommonName: Entrust Root Certification Authority - G2
Subject Key ID   : C3:F7:D0:B5:2A:30:AD:AF:0D:91:21:70:39:54:DD:BC:89:70:C7:3A
Authority Key ID : 6A:72:26:7A:D0:1E:EF:7D:E7:3B:69:51:D4:6C:8D:9F:90:12:66:AB
Basic Constraints: CA:true, pathlen:0
Key Usage:
	Cert Sign
	CRL Sign
Extended Key Usage:
	Client Auth
	Server Auth

** CERTIFICATE 3 **
Serial: 1372799044
Not Before: 2014-09-22 17:14:57 +0000 UTC
Not After : 2024-09-23 01:31:53 +0000 UTC
Signature : SHA256-RSA
Subject Info:
	Country: US
	Organization: Entrust, Inc.
	Organizational Unit: See www.entrust.net/legal-terms
	Organizational Unit: (c) 2009 Entrust, Inc. - for authorized use only
	CommonName: Entrust Root Certification Authority - G2
Issuer Info:
	Country: US
	Organization: Entrust, Inc.
	Organizational Unit: www.entrust.net/CPS is incorporated by reference
	Organizational Unit: (c) 2006 Entrust, Inc.
	CommonName: Entrust Root Certification Authority
Subject Key ID   : 6A:72:26:7A:D0:1E:EF:7D:E7:3B:69:51:D4:6C:8D:9F:90:12:66:AB
Authority Key ID : 68:90:E4:67:A4:A6:53:80:C7:86:66:A4:F1:F7:4B:43:FB:84:BD:6D
Basic Constraints: CA:true, pathlen:1
Key Usage:
	Cert Sign
	CRL Sign

[0] www.squareup.com
	=> Entrust Certification Authority - L1M
	=> Entrust Root Certification Authority - G2 [self-signed]
[1] www.squareup.com
	=> Entrust Certification Authority - L1M
	=> Entrust Root Certification Authority - G2
	=> Entrust Root Certification Authority [self-signed] [SHA1-RSA]
```
