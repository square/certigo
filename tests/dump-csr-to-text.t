Set up test data.

  $ cat > example-leaf.csr <<EOF
  > -----BEGIN CERTIFICATE REQUEST-----
  > MIICmjCCAYICAQAwVTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRAwDgYDVQQK
  > EwdjZXJ0aWdvMRAwDgYDVQQLEwdleGFtcGxlMRUwEwYDVQQDEwxleGFtcGxlLWxl
  > YWYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7stSvfQyGuHw3v34f
  > isqIdDXberrFoFk9ht/WdXgYzX2uLNKdsR/J5sbWSl8K/5djpzj31eIzqU69w8v7
  > SChM5x9bouDsABHz3kZucx5cSafEgJojysBkcrq3VY+aJanzbL+qErYX+lhRpPcZ
  > K6JMWIwar8Y3B2la4yWwieecw2/WfEVvG0M/DOYKnR8QHFsfl3US1dnBM84czKPy
  > t9r40gDk2XiH/lGts5a94rAGvbr8IMCtq0mA5aH3Fx3mDSi3+4MZwygCAHrF5O5i
  > SV9rEI+m2+7j2S+jHDUnvV+nqcpb9m6ENECnYX8FD2KcqlOjTmw8smDy09N2Np6i
  > 464lAgMBAAGgADANBgkqhkiG9w0BAQUFAAOCAQEAZW13CST8BtPCINS0CiIv9BMv
  > zXpkCRz3riPvrPkllnOY3Dp0NQzQkdj3aE4at5GSN9fOTWCQ0tGnjOLAZ8tqHcyg
  > FLgU3MjDcsRvyeQ8mYpCqeUbwq/nHIs33jM/x087lTP7aNXGH4sncxZdIv71+sqF
  > f4WnumxsJUARaeb0AnUZmtAC/OR+9vpiUw+wMMhMbDNCboKYANqnFhWkTKp5/85f
  > eC21haSG55pT7bGvlG9WNawgXJ3WX48yw29dSyDKd/buVM5Andrp7hYVuC57wz0u
  > wng/cxCCQrENS4qSvxOgFiLK2j1LHccMuChPFFGyOyXqBNs9pr8F4/2qPJ7tOw==
  > -----END CERTIFICATE REQUEST-----
  > EOF

Dump an example certificate request (example-leaf.csr)

  $ certigo --verbose dump example-leaf.csr
  warning: certificate requests are not supported
  warning: no certificates found in input

