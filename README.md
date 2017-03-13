# certigo

[![license](http://img.shields.io/badge/license-apache_2.0-blue.svg?style=flat)](https://raw.githubusercontent.com/square/certigo/master/LICENSE)
[![release](https://img.shields.io/github/release/square/certigo.svg?style=flat)](https://github.com/square/certigo/releases)
[![build](https://travis-ci.org/square/certigo.svg?branch=master)](https://travis-ci.org/square/certigo)
[![report](https://goreportcard.com/badge/github.com/square/certigo)](https://goreportcard.com/report/github.com/square/certigo)

Certigo is a utility to examine and validate certificates to help with debugging SSL/TLS issues.

### Features

**Supports all common file formats**: Certigo can read and dump certificates in various formats. It can automatically detect and read from X.509 (DER/PEM), JCEKS/JKS, PKCS7 and PKCS12 files. Certificates can be dumped to a human-readable format, a set of PEM blocks, or a JSON object for use in scripting. 

**Validation and linting**: Not sure if your generated certificate is valid? Certigo can connect to remote servers to display and validate their certificate chains. It can also point out common errors on certififcates, such as using an older X.509 format, signatures with outdated hashes, or keys that are too small. 

**Supports STARTTLS Protocols**: Trying to debug SSL/TLS connections on a database or mail server? Certigo supports establishing connections via StartTLS protocols for MySQL, PostgreSQL, SMTP, LDAP, and FTP, making it possible debug connection issues or scan for expired certificates more easily.

**Scripting support**: All commands in certigo have support for optional JSON output, which can be used in shell scripts to analyze or filter output. Combine certigo with [jq](https://stedolan.github.io/jq) to find all certificates in a bundle that are signed with SHA1-RSA, or filter for CA certificates, or whatever you need!

### Install

To install certigo, simply use:

    go get -u github.com/square/certigo

On macOS you can also use homebrew to install:

    brew install certigo

Note that certigo requires Go 1.8 or later to build.

### Develop

We use [glide][1] for managing vendored dependencies. If you would like to contribute, see the [CONTRIBUTING.md](CONTRIBUTING.md) file for extra information.  

[1]: https://glide.sh

### Usage

Certigo has commands to dump certificates and keystores from a file, to connect and fetch certificates from a remote server, and to verify the validity of certificates in a file. All commands can produce JSON output with the `--json` flag which can be used for scripting. See below for a full list of options. 

```
usage: certigo [<flags>] <command> [<args> ...]

A command line certificate examination utility.

Flags:
      --help     Show context-sensitive help (also try --help-long and --help-man).
  -v, --verbose  Print verbose
      --version  Show application version.

Commands:
  help [<command>...]
    Show help.


  dump [<flags>] [<file>...]
    Display information about a certificate from a file/stdin.

    -f, --format=FORMAT      Format of given input (PEM, DER, JCEKS, PKCS12; heuristic if missing).
    -p, --password=PASSWORD  Password for PKCS12/JCEKS key stores (reads from TTY if missing).
    -m, --pem                Write output as PEM blocks instead of human-readable format.
    -j, --json               Write output as machine-readable JSON format.

  connect [<flags>] [<server:port>]
    Connect to a server and print its certificate(s).

    -n, --name=NAME           Override the server name used for Server Name Indication (SNI).
        --ca=CA               Path to CA bundle (system default if unspecified).
        --cert=CERT           Client certificate chain for connecting to server (PEM).
        --key=KEY             Private key for client certificate, if not in same file (PEM).
    -t, --start-tls=PROTOCOL  Enable StartTLS protocol ('ldap', 'mysql', 'postgres', 'smtp' or 'ftp').
        --timeout=5s          Timeout for connecting to remote server (can be '5m', '1s', etc).
    -m, --pem                 Write output as PEM blocks instead of human-readable format.
    -j, --json                Write output as machine-readable JSON format.

  verify --name=NAME [<flags>] [<file>]
    Verify a certificate chain from file/stdin against a name.

    -f, --format=FORMAT      Format of given input (PEM, DER, JCEKS, PKCS12; heuristic if missing).
    -p, --password=PASSWORD  Password for PKCS12/JCEKS key stores (reads from TTY if missing).
    -n, --name=NAME          Server name to verify certificate against.
        --ca=CA              Path to CA bundle (system default if unspecified).
    -j, --json               Write output as machine-readable JSON format.
```

### Examples

Display information about a certificate (also supports `--pem` and `--json` output):

```
$ certigo dump --verbose squareup-2016.crt
** CERTIFICATE 1 **
Serial: 260680855742043049380997676879525498489
Valid: 2016-07-15 20:15 UTC to 2017-07-31 20:45 UTC
Signature: SHA256-RSA
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
Subject Key ID: D4:17:14:6F:0B:C5:20:A1:D6:FE:21:7E:DC:9E:F8:57:9C:ED:AE:6A
Authority Key ID: C3:F7:D0:B5:2A:30:AD:AF:0D:91:21:70:39:54:DD:BC:89:70:C7:3A
Basic Constraints: CA:false
Key Usage:
	Digital Signature
	Key Encipherment
Extended Key Usage:
	Server Auth
	Client Auth
Alternate DNS Names:
	www.squareup.com, squareup.com, account.squareup.com, mkt.com,
	www.mkt.com, market.squareup.com, gosq.com, www.gosq.com, gosq.co,
	www.gosq.co
```

Display & validate certificates from a remote server (also supports `--start-tls`):

```
$ certigo connect --verbose squareup.com:443
** TLS Connection **
Version: TLS 1.2
Cipher Suite: ECDHE_RSA key exchange, AES_128_GCM_SHA256 cipher

** CERTIFICATE 1 **
Serial: 260680855742043049380997676879525498489
Valid: 2016-07-15 20:15 UTC to 2017-07-31 20:45 UTC
Signature: SHA256-RSA
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
Subject Key ID: D4:17:14:6F:0B:C5:20:A1:D6:FE:21:7E:DC:9E:F8:57:9C:ED:AE:6A
Authority Key ID: C3:F7:D0:B5:2A:30:AD:AF:0D:91:21:70:39:54:DD:BC:89:70:C7:3A
Basic Constraints: CA:false
Key Usage:
	Digital Signature
	Key Encipherment
Extended Key Usage:
	Server Auth
	Client Auth
Alternate DNS Names:
	www.squareup.com, squareup.com, account.squareup.com, mkt.com,
	www.mkt.com, market.squareup.com, gosq.com, www.gosq.com, gosq.co,
	www.gosq.co

** CERTIFICATE 2 **
Serial: 30215777750102225331854468774
Valid: 2014-12-15 15:25 UTC to 2030-10-15 15:55 UTC
Signature: SHA256-RSA
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
Subject Key ID: C3:F7:D0:B5:2A:30:AD:AF:0D:91:21:70:39:54:DD:BC:89:70:C7:3A
Authority Key ID: 6A:72:26:7A:D0:1E:EF:7D:E7:3B:69:51:D4:6C:8D:9F:90:12:66:AB
Basic Constraints: CA:true, pathlen:0
Key Usage:
	Cert Sign
	CRL Sign
Extended Key Usage:
	Client Auth
	Server Auth

** CERTIFICATE 3 **
Serial: 1372799044
Valid: 2014-09-22 17:14 UTC to 2024-09-23 01:31 UTC
Signature: SHA256-RSA
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
Subject Key ID: 6A:72:26:7A:D0:1E:EF:7D:E7:3B:69:51:D4:6C:8D:9F:90:12:66:AB
Authority Key ID: 68:90:E4:67:A4:A6:53:80:C7:86:66:A4:F1:F7:4B:43:FB:84:BD:6D
Basic Constraints: CA:true, pathlen:1
Key Usage:
	Cert Sign
	CRL Sign

Found 2 valid certificate chain(s):
[0] www.squareup.com
	=> Entrust Certification Authority - L1M
	=> Entrust Root Certification Authority - G2 [self-signed]
[1] www.squareup.com
	=> Entrust Certification Authority - L1M
	=> Entrust Root Certification Authority - G2
	=> Entrust Root Certification Authority [self-signed] [SHA1-RSA]
```

Advanced examples on how to combine JSON output with [jq](https://stedolan.github.io/jq/) filtering:

```
# Find certificates that have linter warnings
certigo dump --json $INPUT | jq '.certificates[] | select(.warnings != [])'

# Find certificates that are signed with SHA1-RSA
certigo dump --json $INPUT | jq '.certificates[] | select(.signature_algorithm == "SHA1-RSA")'

# List all Common Names of certificates that are expired
certigo dump --json $INPUT | jq -r '.certificates[] | select(.not_after < now) | .subject.common_name'

# Look for MySQL servers with invalid certificates
for SERVER in $(cat servers); do
  certigo connect -t mysql -j $SERVER:3306 | jq -e '.verify_result.error != null' >/dev/null
  if [ $? -ne 0 ]; then
    echo "Invalid certificates on $SERVER"
  fi
done

# Find (redundant) self-signed certificates in intermediate chain on remote host
certigo connect $SERVER:$PORT | jq -e '.certificates[1:][] | select(.is_self_signed) | .subject.common_name'
```
