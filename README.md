# certigo

[![license](http://img.shields.io/badge/license-apache_2.0-red.svg?style=flat)](https://raw.githubusercontent.com/square/certigo/master/LICENSE)
[![build](https://travis-ci.org/square/certigo.svg?branch=master)](https://travis-ci.org/square/certigo)
[![report](https://goreportcard.com/badge/github.com/square/certigo)](https://goreportcard.com/report/github.com/square/certigo)

Certigo is a utility to examine and validate certificates in a variety of formats.

### Install

To install certigo, simply use:

    go get github.com/square/certigo

Note that certigo requires Go 1.6 or later to build.

### Develop

We use [glide][1] for managing vendored dependencies. 

[1]: https://glide.sh

### Usage

Certigo can read certificates/keystores in various formats and dump them to stdout.

Currently supported formats are DER, PEM, JCEKS and PKCS12. It's a one-stop shop for debugging/analyzing certs.

For example (from stdin):

    $ certigo dump < certificate.pem
    ** CERTIFICATE 1 **
    Serial: 11578389349061131131
    Not Before: 2016-05-27 21:15:31 +0000 UTC
    Not After : 2017-10-09 21:15:31 +0000 UTC
    Signature algorithm: SHA1-RSA
    Subject Info:
    	CommonName: ApertureScience
    	Organization: [Aperture Science]
    	OrganizationalUnit: [Research and Development]
    	Country: [US]
    	Locality: [San Francisco]
    Issuer Info:
    	CommonName: ApertureScience
    	Organization: [Aperture Science]
    	OrganizationalUnit: [Research and Development]
    	Country: [US]
    	Locality: [San Francisco]

Or from a file:

    $ certigo dump keystore.jceks 
    Enter password: some-password
    ** CERTIFICATE 1 **
    Alias: trusted-cert-some-alias
    Serial: 15734933907626610346
    Not Before: 2014-03-14 14:10:45 +0000 UTC
    Not After : 2015-03-14 14:10:45 +0000 UTC
    Signature algorithm: SHA1-RSA
    Subject Info:
    	CommonName: Test User
    	Organization: [Test Organization]
    	Country: [US]
    Issuer Info:
    	CommonName: Test User
    	Organization: [Test Organization]
    	Country: [US]
    	
To dump a cert chain from a TLS server:

    openssl s_client -connect squareup.com:443 -showcerts < /dev/null | certigo dump
    
Unlike `openssl x509 -text`, certigo will dump the entire chain, not just the first certificate.
