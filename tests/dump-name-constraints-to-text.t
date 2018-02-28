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
  > -----BEGIN CERTIFICATE-----
  > MIIEMTCCAxmgAwIBAgIBADANBgkqhkiG9w0BAQUFADCBlTELMAkGA1UEBhMCR1Ix
  > RDBCBgNVBAoTO0hlbGxlbmljIEFjYWRlbWljIGFuZCBSZXNlYXJjaCBJbnN0aXR1
  > dGlvbnMgQ2VydC4gQXV0aG9yaXR5MUAwPgYDVQQDEzdIZWxsZW5pYyBBY2FkZW1p
  > YyBhbmQgUmVzZWFyY2ggSW5zdGl0dXRpb25zIFJvb3RDQSAyMDExMB4XDTExMTIw
  > NjEzNDk1MloXDTMxMTIwMTEzNDk1MlowgZUxCzAJBgNVBAYTAkdSMUQwQgYDVQQK
  > EztIZWxsZW5pYyBBY2FkZW1pYyBhbmQgUmVzZWFyY2ggSW5zdGl0dXRpb25zIENl
  > cnQuIEF1dGhvcml0eTFAMD4GA1UEAxM3SGVsbGVuaWMgQWNhZGVtaWMgYW5kIFJl
  > c2VhcmNoIEluc3RpdHV0aW9ucyBSb290Q0EgMjAxMTCCASIwDQYJKoZIhvcNAQEB
  > BQADggEPADCCAQoCggEBAKlTAOMupvaO+mDYLZU++CwqVE7NuYRhlFhPjz2L5EPz
  > dYmNUeTDN9KKiE15HrcS3UN4SoqS5tdI1Q+kOilENbgH9mgdVc04UfCMJDGFr4PJ
  > fel3r+0ae50X+bOdOFAPplp5kYCvN66m0zH7tSYJnTxa71HFK9+WXesyHgLacEns
  > bgzImjeN9/E2YEsmLIKe0HjzDQ9jpFEw4fkrJxIH2Oq9GGKYsFk3fb7u8yBRQlqD
  > 75O6aRXxYp2fmTmCobd0LovUxQt7L/DICto9eQqakxylKHJzkUOap9FNhYS5qXSP
  > FEDH3N6sQWRstBmbAmNtJGSPRLIl6s5ddAxjMlyNh+UCAwEAAaOBiTCBhjAPBgNV
  > HRMBAf8EBTADAQH/MAsGA1UdDwQEAwIBBjAdBgNVHQ4EFgQUppFC/RNhSiOeCKQp
  > 5dgTBCPuQSUwRwYDVR0eBEAwPqA8MAWCAy5ncjAFggMuZXUwBoIELmVkdTAGggQu
  > b3JnMAWBAy5ncjAFgQMuZXUwBoEELmVkdTAGgQQub3JnMA0GCSqGSIb3DQEBBQUA
  > A4IBAQAf73lB4XtuP7KMhjdCSk4cNx6NZrokgclPEg8hwAOXhiVtXdMiKahsog2p
  > 6z0GW5k6x8zDmjR/qw7IThzh+uTczQ2+vyT+bOdrwg3IBp5OjWEopmr95fZi6hg8
  > TqBTnbI6nOulnJEWtk2C4AwFSKls9cz4y51JtPACpf1wA+2KIaWuE4ZJwzNzvoc7
  > dIsXRSZMFpGD/md9zU1jZ/rzAxKWeAaNsWftjj++n08C9bMJL/NMh98qy5V8Acys
  > Nnq/onN694/BtZqhFLKPM58N7yLcZnuEvUUXBj08yrl3NI/K6s8/MT7jiOOASSXI
  > l7WdmplNsDz4SgCbZN2fOUvRJ9e4
  > -----END CERTIFICATE-----
  > EOF

Dump an example certificate with name constraints (example-name-constraints.crt)

  $ certigo --verbose dump example-name-constraints.crt
  ** CERTIFICATE 1 **
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
  
  ** CERTIFICATE 2 **
  Serial: 0
  Valid: 2011-12-06 13:49 UTC to 2031-12-01 13:49 UTC
  Signature: SHA1-RSA (self-signed)
  Subject Info:
  \tCountry: GR (esc)
  \tOrganization: Hellenic Academic and Research Institutions Cert. Authority (esc)
  \tCommonName: Hellenic Academic and Research Institutions RootCA 2011 (esc)
  Issuer Info:
  \tCountry: GR (esc)
  \tOrganization: Hellenic Academic and Research Institutions Cert. Authority (esc)
  \tCommonName: Hellenic Academic and Research Institutions RootCA 2011 (esc)
  Subject Key ID: A6:91:42:FD:13:61:4A:23:9E:08:A4:29:E5:D8:13:04:23:EE:41:25
  Basic Constraints: CA:true
  Name Constraints:
  Permitted DNS domains:
  \t.gr, .eu, .edu, .org (esc)
  Permitted email addresses:
  \t.gr, .eu, .edu, .org (esc)
  Key Usage:
  \tCert Sign (esc)
  \tCRL Sign (esc)
  Warnings:
  \tSerial number in cert appears to be zero/negative (esc)
  \tSigned with SHA1-RSA, which is an outdated signature algorithm (esc)
  
