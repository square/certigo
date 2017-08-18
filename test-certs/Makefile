TARGETS = \
	example-root example-leaf example-sha1 example-md5 example-root-bad-ku \
	example-bad-serial example-small-key example-expired example-elliptic-sha1 \
	example-custom-oid example-name-constraints

all: \
	$(addsuffix .crt,$(TARGETS)) \
	$(addsuffix .p12,$(TARGETS)) \
	$(addsuffix .p7b,$(TARGETS)) \
	$(addsuffix .jceks,$(TARGETS))

clean:
	rm -f example-*

.PHONY: all clean

# Generic commands
%.key:
	openssl genrsa -out $@ 2048

%.csr: %.key
	openssl req -new -key $< -out $@ -subj /C=US/ST=CA/O=certigo/OU=example/CN=$(@:.csr=)

%.p12: %.crt %.key
	openssl pkcs12 -export -out $@ -in $< -inkey $(@:.p12=.key) -name $(@:.p12=) -password pass:password

%.p7b: %.crt
	openssl crl2pkcs7 -nocrl -certfile $< -out $@

%.jceks: %.p12
	keytool -importkeystore \
		-destkeystore $@ -deststoretype JCEKS -destkeypass password -deststorepass password -destalias $* \
		-srckeystore $< -srcstoretype PKCS12 -srcstorepass password -srcalias $* -storetype JCEKS

# Good root cert
example-root.crt: example-root.csr
	openssl x509 -req -sha256 -in $< -signkey $(@:.crt=.key) -out $@ -days 2500 -extfile openssl.ext -extensions root

# Good leaf cert
example-leaf.crt: example-leaf.csr
	openssl x509 -req -sha256 -in $< -signkey $(@:.crt=.key) -out $@ -days 2500 -extfile openssl.ext -extensions leaf

# Bad cert with SHA-1 instead of SHA-2
example-sha1.crt: example-sha1.csr
	openssl x509 -req -in $< -signkey $(@:.crt=.key) -out $@ -days 2500 -extfile openssl.ext -extensions leaf

# Bad cert with MD-5 instead of SHA-2
example-md5.crt: example-md5.csr
	openssl x509 -req -md5 -in $< -signkey $(@:.crt=.key) -out $@ -days 2500 -extfile openssl.ext -extensions leaf

# Bad root cert with missing "cert sign" key usage
example-root-bad-ku.crt: example-root-bad-ku.csr
	openssl x509 -req -sha256 -in $< -signkey $(@:.crt=.key) -out $@ -days 2500 -extfile openssl.ext -extensions root_bad

# Bad cert with invalid serial
example-bad-serial.crt: example-bad-serial.csr
	openssl x509 -req -sha256 -in $< -signkey $(@:.crt=.key) -out $@ -set_serial 0 -days 2500 -extfile openssl.ext -extensions leaf

# Example with small RSA key
example-small-key.key:
	openssl genrsa -out $@ 1024

example-small-key.crt: example-small-key.csr
	openssl x509 -req -sha256 -in $< -signkey $(@:.crt=.key) -out $@ -days 2500

# Short expiry certificate (OpenSSL requires min. of 1 day, so let's do that)
example-expired.crt: example-expired.csr
	openssl x509 -req -sha256 -in $< -signkey $(@:.crt=.key) -out $@ -days 1

# Example ECC key
example-elliptic-sha1.key:
	openssl ecparam -genkey -name secp521r1 -out $@

example-elliptic-sha1.crt: example-elliptic-sha1.csr
	openssl x509 -req -in $< -signkey $(@:.crt=.key) -out $@ -days 2500 -extfile openssl.ext -extensions leaf

# Custom OID
example-custom-oid.csr: example-custom-oid.key
	openssl req -new -config example-custom-oid.conf -key $< -out $@

example-custom-oid.crt: example-custom-oid.csr
	openssl x509 -req -sha256 -in $< -signkey $(@:.crt=.key) -out $@ -days 2500 -extfile openssl.ext -extensions leaf

example-name-constraints.crt: example-name-constraints.csr
	openssl x509 -req -sha256 -in $< -signkey $(@:.crt=.key) -out $@ -days 2500 -extfile openssl.ext -extensions root_with_constraints
