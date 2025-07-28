#!/bin/sh
if ! [ -d testdata ]; then
  echo "Must be called in parent directory of testdata" >&2
  exit 1
fi

cd testdata

rm -f "private-key-ca.key" "private-key-ca.crt" "private-key.key" "private-key.csr" "private-key-ca.srl" \
  "private-key.crt" "private-key.p12" "private-key.jceks"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -subj "/CN=Test CA/O=Test Organization/C=US" -extensions v3_req \
  -keyout "private-key-ca.key" -out "private-key-ca.crt"
openssl genrsa -out "private-key.key" 2048
openssl req -new -key "private-key.key" \
  -subj "/CN=Test User/O=Test Organization/C=US" -subj "/CN=Test User/O=Test Organization/C=US" -extensions v3_req \
  -out "private-key.csr"
openssl x509 -req -in "private-key.csr" -CA "private-key-ca.crt" -CAkey "private-key-ca.key" \
  -CAcreateserial -out "private-key.crt" -days 365
openssl pkcs12 -export -in "private-key.crt" -certfile "private-key-ca.crt" -inkey "private-key.key" \
  -name "private-key-some-alias"  -out "private-key.p12" -passout "pass:store-password"
keytool -importkeystore -alias "private-key-some-alias" \
  -srckeystore "private-key.p12" -srcstoretype PKCS12 -srcstorepass "store-password" \
  -destkeystore "private-key.jceks" -storetype JCEKS -deststorepass "store-password" -destkeypass "key-password"
rm -f "private-key-ca.key" "private-key.csr" "private-key-ca.srl" "private-key.p12"

rm -f "trusted-cert.key" "trusted-cert.crt" "trusted-cert.jceks"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -subj "/CN=Test User/O=Test Organization/C=US" -extensions v3_req \
  -keyout "trusted-cert.key" -out "trusted-cert.crt"
keytool -importcert -noprompt -alias "trusted-cert-some-alias" \
  -file "trusted-cert.crt" \
  -destkeystore "trusted-cert.jceks" -storetype JCEKS -deststorepass "store-password"
rm -f "trusted-cert.key"

go test github.com/square/certigo/jceks -jceks.write-reencoded=true
