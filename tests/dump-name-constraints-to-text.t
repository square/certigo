Set up test data.

  $ cat > example-name-constraints.crt <<EOF
  > -----BEGIN CERTIFICATE-----
  > MIID1DCCArygAwIBAgIJAL8xOGAOaSzBMA0GCSqGSIb3DQEBCwUAMGExCzAJBgNV
  > BAYTAlVTMQswCQYDVQQIEwJDQTEQMA4GA1UEChMHY2VydGlnbzEQMA4GA1UECxMH
  > ZXhhbXBsZTEhMB8GA1UEAxMYZXhhbXBsZS1uYW1lLWNvbnN0cmFpbnRzMB4XDTE3
  > MDgxODE5NDg1MFoXDTI0MDYyMjE5NDg1MFowYTELMAkGA1UEBhMCVVMxCzAJBgNV
  > BAgTAkNBMRAwDgYDVQQKEwdjZXJ0aWdvMRAwDgYDVQQLEwdleGFtcGxlMSEwHwYD
  > VQQDExhleGFtcGxlLW5hbWUtY29uc3RyYWludHMwggEiMA0GCSqGSIb3DQEBAQUA
  > A4IBDwAwggEKAoIBAQDkrrryvC1a63Vc2yCBb0SliieU6TnqZAQ5rJzAa4zf7uq9
  > obwLuGfZV5j/7nYl04M2gPiz4Rk8uia14tIqBjFjB5DH7czuaPiGKgMSKMXt9lPZ
  > xu3ZnRLRmF+I/zlIjxqLU9bxem7Qs7RBoncbbd65gy8PPe2J09rJdrcj5V/hD2jZ
  > pNWtrYA6ANGsMSxLchtpn3LKyDy/bW2HIhXmqVIq/2j2p2ljKf6E63L4S7e7FW8E
  > MGiW9y+DLO5U7qSZUiqgAiXHjTKWtYgbnlqboPtZRV5quN2PE0KD3FOLhAQX5MKS
  > 3P48+cjeswmruNVc8qjdCi1NLsRCTHukM/WxAC35AgMBAAGjgY4wgYswDgYDVR0P
  > AQH/BAQDAgIEMBIGA1UdEwEB/wQIMAYBAf8CAQAwZQYDVR0eBF4wXKAsMA6CDC5l
  > eGFtcGxlLmNvbTAKhwjAqAAA//8AADAOgQwuZXhhbXBsZS5jb22hLDAOggwuZXhh
  > bXBsZS5vcmcwCocICgoAAP//AAAwDoEMLmV4YW1wbGUub3JnMA0GCSqGSIb3DQEB
  > CwUAA4IBAQBDxhzTZc0fB7B2EvHmzz45J3xgk/aQksKFXeWxyX7UdgSY+gzABRMk
  > txHCMZtdTJxi4BACpRlO4QMbJXSiofhGJQb+ThSvM1CQv+W5X4j7/40RBfRnWbQP
  > ZGfxSyGhLYAIzUsHi6X7DbJmzV2EixPbYKCJ+5Vlf7IH0aDexzf4xKLQdy+cWy1g
  > Y4bHiiQbVqfTjlzdsMuiFqoZe3/NhOP93XSMZErx6pJ/lrWiO+6ytM3gdwh1y0DE
  > tFmaBKzI+2uQwt6DHQuPmOSEmI7NcrVS2WhPVPa7fIY/ExUy7jqIr2qM59eSl7OC
  > AhzgLtgqfwLgbj5PWZENYlNRXmZGi4GD
  > -----END CERTIFICATE-----
  > EOF

Dump an example certificate with name constraints (example-name-constraints.crt)

  $ certigo --verbose dump example-name-constraints.crt
  ** CERTIFICATE 1 **
  Input Format: PEM
  Serial: 13776854720312847553
  Valid: 2017-08-18 19:48 UTC to 2024-06-22 19:48 UTC
  Signature: SHA256-RSA (self-signed)
  Subject Info:
  \tCountry: US (esc)
  \tProvince: CA (esc)
  \tOrganization: certigo (esc)
  \tOrganizational Unit: example (esc)
  \tCommonName: example-name-constraints (esc)
  Issuer Info:
  \tCountry: US (esc)
  \tProvince: CA (esc)
  \tOrganization: certigo (esc)
  \tOrganizational Unit: example (esc)
  \tCommonName: example-name-constraints (esc)
  Basic Constraints: CA:true, pathlen:0
  Name Constraints:
  Permitted DNS domains:
  \t.example.com (esc)
  Permitted email addresses:
  \t.example.com (esc)
  Permitted IP ranges:
  \t192.168.0.0/16 (esc)
  Excluded DNS domains:
  \t.example.org (esc)
  Excluded email addresses:
  \t.example.org (esc)
  Excluded IP ranges:
  \t10.10.0.0/16 (esc)
  Key Usage:
  \tCert Sign (esc)
  Warnings:
  \t[e_ext_subject_key_identifier_missing_ca]  (esc)
  \t[e_ext_name_constraints_not_critical]  (esc)