Set up test data.

  $ cat > example-leaf.crt <<EOF
  > -----BEGIN CERTIFICATE-----
  > MIIDfDCCAmSgAwIBAgIJANWAkzF7PA8/MA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV
  > BAYTAlVTMQswCQYDVQQIEwJDQTEQMA4GA1UEChMHY2VydGlnbzEQMA4GA1UECxMH
  > ZXhhbXBsZTEVMBMGA1UEAxMMZXhhbXBsZS1sZWFmMB4XDTE2MDYxMDIyMTQxMVoX
  > DTIzMDQxNTIyMTQxMVowVTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRAwDgYD
  > VQQKEwdjZXJ0aWdvMRAwDgYDVQQLEwdleGFtcGxlMRUwEwYDVQQDEwxleGFtcGxl
  > LWxlYWYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7stSvfQyGuHw3
  > v34fisqIdDXberrFoFk9ht/WdXgYzX2uLNKdsR/J5sbWSl8K/5djpzj31eIzqU69
  > w8v7SChM5x9bouDsABHz3kZucx5cSafEgJojysBkcrq3VY+aJanzbL+qErYX+lhR
  > pPcZK6JMWIwar8Y3B2la4yWwieecw2/WfEVvG0M/DOYKnR8QHFsfl3US1dnBM84c
  > zKPyt9r40gDk2XiH/lGts5a94rAGvbr8IMCtq0mA5aH3Fx3mDSi3+4MZwygCAHrF
  > 5O5iSV9rEI+m2+7j2S+jHDUnvV+nqcpb9m6ENECnYX8FD2KcqlOjTmw8smDy09N2
  > Np6i464lAgMBAAGjTzBNMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAs
  > BgNVHREEJTAjhwR/AAABhxAAAAAAAAAAAAAAAAAAAAABgglsb2NhbGhvc3QwDQYJ
  > KoZIhvcNAQELBQADggEBAGM4aa/qrURUweZBIwZYv8O9b2+r4l0HjGAh982/B9sM
  > lM05kojyDCUGvj86z18Lm8mKr4/y+i0nJ+vDIksEvfDuzw5ALAXGcBzPJKtICUf7
  > LstA/n9NNpshWz0kld9ylnB5mbUzSFDncVyeXkEf5sGQXdIIZT9ChRBoiloSaa7d
  > vBVCcsX1LGP2LWqKtD+7nUnw5qCwtyAVT8pthEUxFTpywoiJS5ZdzeEx8MNGvUeL
  > Fj2kleqPF78EioEQlSOxViCuctEtnQuPcDLHNFr10byTZY9roObiqdsJLMVvb2Xl
  > iJjAqaPa9AkYwGE6xHw2ispwg64Rse0+AtKups19WIU=
  > -----END CERTIFICATE-----
  > EOF

Dump an example certificate (example-leaf.crt)

  $ certigo --verbose dump example-leaf.crt
  ** CERTIFICATE 1 **
  Input Format: PEM
  Serial: 15384458167827828543
  Valid: 2016-06-10 22:14 UTC to 2023-04-15 22:14 UTC
  Signature: SHA256-RSA
  Subject Info:
  \tCountry: US (esc)
  \tProvince: CA (esc)
  \tOrganization: certigo (esc)
  \tOrganizational Unit: example (esc)
  \tCommonName: example-leaf (esc)
  Issuer Info:
  \tCountry: US (esc)
  \tProvince: CA (esc)
  \tOrganization: certigo (esc)
  \tOrganizational Unit: example (esc)
  \tCommonName: example-leaf (esc)
  Extended Key Usage:
  \tClient Auth (esc)
  \tServer Auth (esc)
  DNS Names:
  \tlocalhost (esc)
  IP Addresses:
  \t127.0.0.1, ::1 (esc)
  Lints:
  \tERROR: [RFC5280] CAs must include keyIdentifer field of AKI in all non-self-issued certificates (esc)
  \tWARN: [RFC5280] Sub certificates SHOULD include Subject Key Identifier in end entity certs (esc)
  