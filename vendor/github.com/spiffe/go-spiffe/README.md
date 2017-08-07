# go-spiffe library

### Overview
The go-spiffe library provides functionality to parse and verify SPIFFE identities encoded in X.509 certificates as described in the [SPIFFE Verifiable Identity Document (SVID) Document Specification](https://github.com/spiffe/svid/blob/master/SPECIFICATION.md).

#### func GetUrisInSubjectAltName

```go
func GetUrisInSubjectAltName(certificateString string) (uris []string, err error)
```
Parses an X.509 certificate in PEM format and gets the URIs from the Subject Alternative Name extension.