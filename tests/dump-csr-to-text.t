Set up test data.

  $ cat > ec-req.pem <<EOF
  > -----BEGIN CERTIFICATE REQUEST-----
  > MIIBPzCB5gIBADCBgzELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQH
  > DAlCYW5nYWxvcmUxEDAOBgNVBAoMB0NlcnRpZ28xEDAOBgNVBAsMB0luZm9TZWMx
  > GTAXBgNVBAMMEHRlc3QuY2VydGlnby5jb20xFDASBgkqhkiG9w0BCQEWBWFAYi5j
  > MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt434uInYNO41D/otGSIRGhzlUWW3
  > uiZqstGh7Tf47hKgXX7Mnq3iukPv6Zpoy72SrOVrNJBsv4gsYYLScjhgF6AAMAoG
  > CCqGSM49BAMCA0gAMEUCIH8plgdk1nT3GaVM9u/FwQbrFNkFnj9Nr1fAGLc6XNFY
  > AiEAoqtThEy7IvRLtQG0ZBnaaBlReyygpyMxSJPniciKONs=
  > -----END CERTIFICATE REQUEST-----
  > EOF

  $ certigo --verbose dump --csr ec-req.pem
  ** CERTIFICATE REQUEST 1 **
  Signature: ECDSA-SHA256
  Subject Info:
  \tCountry: IN (esc)
  \tProvince: KA (esc)
  \tLocality: Bangalore (esc)
  \tOrganization: Certigo (esc)
  \tOrganizational Unit: InfoSec (esc)
  \tCommonName: test.certigo.com (esc)
  \tEmail Address: a@b.c (esc)
  Warnings:
  \tCertificate Request is not in X509v3 format (version is 0) (esc)
  \tCertificate Request doesn't have any valid DNS/URI names or IP addresses set (esc)
  
Testing with normal certs 
  $ cat > example-sha1.csr<<EOF
  > -----BEGIN CERTIFICATE REQUEST-----
  > MIICmjCCAYICAQAwVTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRAwDgYDVQQK
  > EwdjZXJ0aWdvMRAwDgYDVQQLEwdleGFtcGxlMRUwEwYDVQQDEwxleGFtcGxlLXNo
  > YTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCUuAbvyfPJsBEr41hy
  > eAX26jhZJWVbioCveouRbgfO9JQOdHxKRNJtWiI2+rVwUfIRxF9qO/wsNeRDHjsb
  > W5KD4prsp8RNLZJqVKm171XwCCUSDeiHTUJfTzsMiV2PwwbzQOK41m0uywtrhEUL
  > cW9+Z+UZ7wnE6+NlU9aLNGEZ94hh3BsnKip/pGHGsIh14vaXE4M+OTJvXkUs/6/d
  > L2yBdiZiw9bqv1GIU3vliI5h28tjB118duwf7ZMqxoRQ32wsUmskNMN/S0OLoS/9
  > BTNyGH2vG/juZnt//Wh35563cun2Qp0va8WzNTRrqRtULfn/+5CwaswnutervIu9
  > 9xnxAgMBAAGgADANBgkqhkiG9w0BAQUFAAOCAQEAECEYs5iOXzghMNgRB0bCgCKA
  > Gw8hfiDCZ1qJLei+ozK8lndbWmXnqDBKPUQnNrLcMHRIrqL1h1nS2wDXJjRn8Tdk
  > CyvGGWpTfN2weOtcxoOs/kQLN5AJWfOhmPmBoImAt9CJw5zRL1d7CRU/+DoZY3Fr
  > FTZM8hHPghL5O838535sqerwIGFtkX6LkFG/gkz6JzZHI1fusEx73FpgNj3UaBZ4
  > zOlEkbtOAABq8RVGNXZ5DJQLCTsu0p9w6jsgcYs3PYNyFoW1RMUcTvDEWCExLLr4
  > m0syZsTfgBNuhaCUNr97BNHR0t1Uy1AnSACZpYdwi254gp0nL5673/CYbZT38A==
  > -----END CERTIFICATE REQUEST-----
  > EOF

  $ certigo --verbose dump --csr example-sha1.csr
  ** CERTIFICATE REQUEST 1 **
  Signature: SHA1-RSA
  Subject Info:
  \tCountry: US (esc)
  \tProvince: CA (esc)
  \tOrganization: certigo (esc)
  \tOrganizational Unit: example (esc)
  \tCommonName: example-sha1 (esc)
  Warnings:
  \tCertificate Request is not in X509v3 format (version is 0) (esc)
  \tCertificate Request doesn't have any valid DNS/URI names or IP addresses set (esc)
  \tSigned with SHA1-RSA, which is an outdated signature algorithm (esc)
  
Testing JSON dump
  $ cat > example-root.csr<<EOF
  > -----BEGIN CERTIFICATE REQUEST-----
  > MIICmjCCAYICAQAwVTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRAwDgYDVQQK
  > EwdjZXJ0aWdvMRAwDgYDVQQLEwdleGFtcGxlMRUwEwYDVQQDEwxleGFtcGxlLXJv
  > b3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKOEoSiNjMQ8/zUFcQ
  > W89LWw+UeTXKGwNDSpGjyi8jBKZ1lWPbnMmrjI6DZ9ReevHHzqBdKZt+9NFPFEz7
  > djDMRByIuJhRvzhfFBflaIdSeNk2+NpUaFuUUUd6IIePu0AdRveJ8ZGHXRwCeEDI
  > VCZS4oBYPHOhX/zMWDg8vSO4pSxTjGc7I8fHxaUSkVzUBbeO9T/1eFk0m2uxs3Uz
  > iUck2X/8YqRd+p/EaBED78nXvKRALAguKAzqxIgk3ccPK0SVQFNFq+eV1/qo8cou
  > eQuqMpCAvwVkfpVKhneyC2NlMrfzlcZZbfG/irlSjQn5+ExZX4Isy1pCUbOiVfSr
  > sCdtAgMBAAGgADANBgkqhkiG9w0BAQUFAAOCAQEAoDcBLidVU6KA9IlID32P3uox
  > fjKsbJee6mswMBqkFKqgdv/vHMiXAttiVxB+Y5AQnkb+kMCl8KwVaXgH145drahz
  > 0aTH6Rxqrf+1OfStQ+Y1CZgRL26vpafvd3xFE7151upO+dUraiYt9736umoStuqX
  > WuqV9EZ5RmvhqEW6cIa6zG5KVlHgDs72jC1f+7nAsj3V3EBqwf/NtOMz+whFo3LB
  > DJU4djTjLiROa/bWI1ZvhKjFf6EWQnZIeGhZLyS8Y+0qoiI1ojhrOYYAdOOHGTV5
  > RJqViMG2o7YxaMYA/QCaYVmkiTlfwR9fZrZOG4lHZ6PyTLtwkHYXkmCgUW237w==
  > -----END CERTIFICATE REQUEST-----
  > EOF

  $ certigo dump --csr example-root.csr --json
  {"certificate_requests":[{"signature_algorithm":"SHA1-RSA","public_key_algorithm":"RSA","subject":{"common_name":"example-root","country":["US"],"organization":["certigo"],"organizational_unit":["example"],"province":["CA"]},"warnings":["Certificate Request is not in X509v3 format (version is 0)","Certificate Request doesn't have any valid DNS/URI names or IP addresses set","Signed with SHA1-RSA, which is an outdated signature algorithm"],"pem":"-----BEGIN CERTIFICATE REQUEST-----\nMIICmjCCAYICAQAwVTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRAwDgYDVQQK\nEwdjZXJ0aWdvMRAwDgYDVQQLEwdleGFtcGxlMRUwEwYDVQQDEwxleGFtcGxlLXJv\nb3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKOEoSiNjMQ8/zUFcQ\nW89LWw+UeTXKGwNDSpGjyi8jBKZ1lWPbnMmrjI6DZ9ReevHHzqBdKZt+9NFPFEz7\ndjDMRByIuJhRvzhfFBflaIdSeNk2+NpUaFuUUUd6IIePu0AdRveJ8ZGHXRwCeEDI\nVCZS4oBYPHOhX/zMWDg8vSO4pSxTjGc7I8fHxaUSkVzUBbeO9T/1eFk0m2uxs3Uz\niUck2X/8YqRd+p/EaBED78nXvKRALAguKAzqxIgk3ccPK0SVQFNFq+eV1/qo8cou\neQuqMpCAvwVkfpVKhneyC2NlMrfzlcZZbfG/irlSjQn5+ExZX4Isy1pCUbOiVfSr\nsCdtAgMBAAGgADANBgkqhkiG9w0BAQUFAAOCAQEAoDcBLidVU6KA9IlID32P3uox\nfjKsbJee6mswMBqkFKqgdv/vHMiXAttiVxB+Y5AQnkb+kMCl8KwVaXgH145drahz\n0aTH6Rxqrf+1OfStQ+Y1CZgRL26vpafvd3xFE7151upO+dUraiYt9736umoStuqX\nWuqV9EZ5RmvhqEW6cIa6zG5KVlHgDs72jC1f+7nAsj3V3EBqwf/NtOMz+whFo3LB\nDJU4djTjLiROa/bWI1ZvhKjFf6EWQnZIeGhZLyS8Y+0qoiI1ojhrOYYAdOOHGTV5\nRJqViMG2o7YxaMYA/QCaYVmkiTlfwR9fZrZOG4lHZ6PyTLtwkHYXkmCgUW237w==\n-----END CERTIFICATE REQUEST-----\n"}]}

Testing depth flag
  $ cat > test.csr<<EOF
  > -----BEGIN CERTIFICATE REQUEST-----
  > MIIBPzCB5gIBADCBgzELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQH
  > DAlCYW5nYWxvcmUxEDAOBgNVBAoMB0NlcnRpZ28xEDAOBgNVBAsMB0luZm9TZWMx
  > GTAXBgNVBAMMEHRlc3QuY2VydGlnby5jb20xFDASBgkqhkiG9w0BCQEWBWFAYi5j
  > MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt434uInYNO41D/otGSIRGhzlUWW3
  > uiZqstGh7Tf47hKgXX7Mnq3iukPv6Zpoy72SrOVrNJBsv4gsYYLScjhgF6AAMAoG
  > CCqGSM49BAMCA0gAMEUCIH8plgdk1nT3GaVM9u/FwQbrFNkFnj9Nr1fAGLc6XNFY
  > AiEAoqtThEy7IvRLtQG0ZBnaaBlReyygpyMxSJPniciKONs=
  > -----END CERTIFICATE REQUEST-----
  > -----BEGIN CERTIFICATE REQUEST-----
  > MIICmjCCAYICAQAwVTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRAwDgYDVQQK
  > EwdjZXJ0aWdvMRAwDgYDVQQLEwdleGFtcGxlMRUwEwYDVQQDEwxleGFtcGxlLXJv
  > b3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKOEoSiNjMQ8/zUFcQ
  > W89LWw+UeTXKGwNDSpGjyi8jBKZ1lWPbnMmrjI6DZ9ReevHHzqBdKZt+9NFPFEz7
  > djDMRByIuJhRvzhfFBflaIdSeNk2+NpUaFuUUUd6IIePu0AdRveJ8ZGHXRwCeEDI
  > VCZS4oBYPHOhX/zMWDg8vSO4pSxTjGc7I8fHxaUSkVzUBbeO9T/1eFk0m2uxs3Uz
  > iUck2X/8YqRd+p/EaBED78nXvKRALAguKAzqxIgk3ccPK0SVQFNFq+eV1/qo8cou
  > eQuqMpCAvwVkfpVKhneyC2NlMrfzlcZZbfG/irlSjQn5+ExZX4Isy1pCUbOiVfSr
  > sCdtAgMBAAGgADANBgkqhkiG9w0BAQUFAAOCAQEAoDcBLidVU6KA9IlID32P3uox
  > fjKsbJee6mswMBqkFKqgdv/vHMiXAttiVxB+Y5AQnkb+kMCl8KwVaXgH145drahz
  > 0aTH6Rxqrf+1OfStQ+Y1CZgRL26vpafvd3xFE7151upO+dUraiYt9736umoStuqX
  > WuqV9EZ5RmvhqEW6cIa6zG5KVlHgDs72jC1f+7nAsj3V3EBqwf/NtOMz+whFo3LB
  > DJU4djTjLiROa/bWI1ZvhKjFf6EWQnZIeGhZLyS8Y+0qoiI1ojhrOYYAdOOHGTV5
  > RJqViMG2o7YxaMYA/QCaYVmkiTlfwR9fZrZOG4lHZ6PyTLtwkHYXkmCgUW237w==
  > -----END CERTIFICATE REQUEST-----
  > EOF

  $ certigo dump --depth 1 --csr test.csr 
  ** CERTIFICATE REQUEST 1 **
  Subject:
  \tC=IN, ST=KA, L=Bangalore, O=Certigo, OU=InfoSec, (esc)
  \tCN=test.certigo.com (esc)
  Warnings:
  \tCertificate Request is not in X509v3 format (version is 0) (esc)
  \tCertificate Request doesn't have any valid DNS/URI names or IP addresses set (esc)
  