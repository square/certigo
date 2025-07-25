Set up test data.

  $ base64 --decode > example.p12 <<EOF
  > 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
  > 80XXrt5bwvUCAggA
  > EOF

Dump PEM blocks from a PKCS12 keystore.

  $ certigo --verbose dump --pem --password password example.p12
  -----BEGIN CERTIFICATE-----
  MIIDLDCCAhQCCQCa74bQsAj2/jANBgkqhkiG9w0BAQsFADBYMQswCQYDVQQGEwJV
  UzELMAkGA1UECBMCQ0ExEDAOBgNVBAoTB2NlcnRpZ28xEDAOBgNVBAsTB2V4YW1w
  bGUxGDAWBgNVBAMTD2V4YW1wbGUtZXhwaXJlZDAeFw0xNjA2MTAyMjE0MTJaFw0x
  NjA2MTEyMjE0MTJaMFgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEQMA4GA1UE
  ChMHY2VydGlnbzEQMA4GA1UECxMHZXhhbXBsZTEYMBYGA1UEAxMPZXhhbXBsZS1l
  eHBpcmVkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs6JY7Hm/NAsH
  3nuMOOSBno6WmwsTYEw3hk4eyprWiI/NpoiaiZVCGahT8NAKqLDW5t9vgKz6c4ff
  i5/aQ2scichq3QS7pELAYlS4b+ey3dA6hj62MOTTO4Ad5bFbbRZG+Mdm2Ayvl6eV
  6catQhMvxt7aIoY9+bodyIYC1zZVqwQ5sOT+CPLDnxK+GvhoyD2jL/XwZplWiIVL
  oX6eEpKIo/QtB6mSU216F/PuAzl/BJond+RzF9mcxJjdZYZlhwT8+o8oXEMI4vEf
  3yzd+zB/mjuxDJR2iw3bSL+zZr2GV/CsMLG/jmvbpIuyI/p5eTy0alz+iHOiyeCN
  9pgD6jyonwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAMUuv/zVYniJ94GdOVcNJ/
  bL3CxR5lo6YB04S425qsVrmOex3IQBL1fUduKSSxh5nF+6nzhRzRrDzp07f9pWHL
  ZHt6rruVhE1Eqt7TKKCtZg0d85lmx5WddL+yWc5cI1UtCohB9+iZDPUBUR9RcszQ
  dGD9PmxnPc9soEcQw/3iNffhMMpLRhPaRW9qtJU8wk16DZunWR8E0Oeq42jVTnb4
  ZiD1Idajj0tj/rT5/M1K/ZLEiOzXVpo/+l/+hoXw9eVnRa2nBwjoiZ9cMuGKUpHm
  YSv7SyFevNwDwcxcAq6uVitKi0YCqHiNZ7Ye3/BGRDUFpK2IASUo8YbXYNyA/6nu
  -----END CERTIFICATE-----
  -----BEGIN RSA PRIVATE KEY-----
  MIIEowIBAAKCAQEAs6JY7Hm/NAsH3nuMOOSBno6WmwsTYEw3hk4eyprWiI/Npoia
  iZVCGahT8NAKqLDW5t9vgKz6c4ffi5/aQ2scichq3QS7pELAYlS4b+ey3dA6hj62
  MOTTO4Ad5bFbbRZG+Mdm2Ayvl6eV6catQhMvxt7aIoY9+bodyIYC1zZVqwQ5sOT+
  CPLDnxK+GvhoyD2jL/XwZplWiIVLoX6eEpKIo/QtB6mSU216F/PuAzl/BJond+Rz
  F9mcxJjdZYZlhwT8+o8oXEMI4vEf3yzd+zB/mjuxDJR2iw3bSL+zZr2GV/CsMLG/
  jmvbpIuyI/p5eTy0alz+iHOiyeCN9pgD6jyonwIDAQABAoIBAA4wn+emQmVhDbEU
  f2IrItYcm2cJ+/DadHRmjWYhzxqgiXVDSzndEYinVGIsfPsQZRl9wvgeMfaYYB9O
  dFZpCqsTquVkr1Htd/cMjDlCy01cWpMqNwgru0fy+emgFgHLBbY3QjeE4QYQ1fXO
  nPcgPuDtz7t0cUbd3eZuN6E6iI/mtpBbN0MrgKb/tlQqFBpSWgcUhu2B9foKg8X5
  6PHbW9eJ5ZPqJ03+86vFVtLmJ93APCZb/W5sRNNdq8Ey0dauKyJr4x++w+GHsW5Q
  8JTdkaIFWU0nc1oO8EXZeZzxPrVHzcxktOmUrhudXG349z1PA5eizlqjOkhFl5/E
  qwSa9zkCgYEA59FD1UbT5SO1MJDsUzLqMIbT4Oe07joLLjsI2aBwvTbXE/t2GCTe
  38Gu2b4LzKLTWJpeEMiD6RVPfzU/5A0ZabUawlOcVXcsjrxKEHjQmVdf6wPuGYf7
  figI3PnKwub5Z0jdHzlgLXQlqLW9mDfmnmSD08PihA++Tnpa4MChs3sCgYEAxl+E
  TLBhPTPLQ92YwUCMDN9NYL1NkAOvYZEZ5OVu5ro35Mnzud2LzPyqt8m0Qq4fITgC
  tdvvOvJ2wa/5nCd80U0eR7Ci9hB0qJMq2xFsrqaZWNMPEoQSMvU2DFq1XU1WQfpy
  s4EgEaq2oycPeYvLbz89TYJGmoYefrafzLYXlC0CgYBWDZCos0olXUP9a07O86+L
  pAEzE9BOPq2306JNZwlys9DTUh1ciRNS7IsDuVCX/jmGQod4o3aUJ50DE7lL5rDw
  VJJCYNc/wqV/ttWnl7GXup+YljTktV3eTu47WV6zSxp6BMpQtPPG676vCgf/YYDy
  e02UZrrHWzDB4RmrJNbh0QKBgQCFV+1hc2pZrngizVECDjZV7MBhl74MYT3Bsrya
  LVMnyuMJamrndDGl/+1tjysZa1vHg5Pm1Mjxccw8E+MQgUaYlmMVQ3m3N4aDTjGP
  gh3xJFGN8ImAI8Dr+gJzuYGSDws9XHE/kjuRRJRyBS6UwFBmHjdB46E7+42CFZZD
  D9+3nQKBgGlX4cwGan4tBVBHorU8925Gk6nmyrzPQ+riA+KYiPXIZ5/WtPAhV86D
  GtZ2VVSqRprAcwQopp9SBfnFy0NHErrPm2telmIRqlxii9ipda4Tek2QgGoREOrq
  gjzEnBf5gy/YRJkylVeH9FY7+HsaBO4kSEOH7GIOe0UpcShJKd+6
  -----END RSA PRIVATE KEY-----
