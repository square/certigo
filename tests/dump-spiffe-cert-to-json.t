Set up test data.

  $ cat > example-spiffe.crt <<EOF
  > -----BEGIN CERTIFICATE-----
  > MIIE1DCCArygAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwPzELMAkGA1UEBhMCVVMx
  > FzAVBgNVBAoMDnRlc3QxLmFjbWUuY29tMRcwFQYDVQQDDA5JbnRlcm1lZGlhZXRD
  > QTAeFw0xNzA3MTkxNjUwMjBaFw0xNzA3MjkxNjUwMjBaMDUxCzAJBgNVBAYTAlVT
  > MRcwFQYDVQQKDA50ZXN0MS5hY21lLmNvbTENMAsGA1UEAwwEYmxvZzCCASIwDQYJ
  > KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKm8P47lABp4+rz2nN+QYrxedbaFVWoF
  > FuoSkqcHsafMwbMrN+kI6wJVtlbwviDvxWFJ92q0H71QNFybTsmof3KUN/kYCp7P
  > +LKhBrN0ttWI5q6v5eDrjN0VdtVdnlZOYmJFbvETOgfK/qXKNRRM8HYW0tdqrtEw
  > CR5dIu53xVUSViBdwXpuy2c5W2mFn1gxTpdW+3hbZsL1pHrU9qPWLtTgl/KY8kjs
  > I7KW1cIcinE4SJomhB5L/4emhxKGY+kEa2+fN9IPjjvKSMOw9kiBKk1GHZcIY5EA
  > O3TIfUk3fysPzi5qA0su/bNtPQy1uXgXS10xUlV7pqRPvHjiNzgFkXUCAwEAAaOB
  > 4zCB4DAJBgNVHRMEAjAAMB0GA1UdDgQWBBRVQ91jSOONzVr1VGBdJOlPN+3XxTBg
  > BgNVHSMEWTBXgBQ13bfx50rDZO3y2CZdHPgleFUEoKE7pDkwNzELMAkGA1UEBhMC
  > VVMxFzAVBgNVBAoMDnRlc3QxLmFjbWUuY29tMQ8wDQYDVQQDDAZSb290Q0GCAhAA
  > MA4GA1UdDwEB/wQEAwIDqDATBgNVHSUEDDAKBggrBgEFBQcDATAtBgNVHREEJjAk
  > hiJzcGlmZmU6Ly9kZXYuYWNtZS5jb20vcGF0aC9zZXJ2aWNlMA0GCSqGSIb3DQEB
  > CwUAA4ICAQBp2+rtUxt1VmNM/vi6PwoSoYzWFmQ2nc4OM7bsOG4uppU54wRYZ+T7
  > c42EcrpyBgWn+rWHT1Hi6SNcmloKHydaUTZ4pq3IlKKnBNqwivU5BzIxYLDrhR/U
  > wd9s1tgmLvADqkQa1XjjSFn5Auoj1R640ry4qpw8IOusdm6wVhru4ssRnHX4E2uR
  > jQe7b3ws38aZhjtL78Ip0BB4yPxWJRp/WmEoT33QP+cZhA4IYWECxNODr6DSJeq2
  > VNu/6JACGrNfM2Sjt4Wxz+nIa3cKDNCA6PR8StTUTcoQ6ZBzpn+n/Q1xSRIOJz6N
  > hgfkyb9O7HAMdAP+TxehjqG3gh5Ky2DgYMCIZOztVzsuOb1DGJe/kGUKeRJLl2/O
  > QwkctwUOcVIxckNu6OvclriFzvoXObqO77XeCI2V1Vef0wGTWlWNOdbFa4708Y7f
  > 5UdwInYQUi87RFDnc1SDU4Jrsv4KzZiv9FCfDg8pCBIdWpWT7DAuI0d7i7PZ+iFt
  > ZZ6sb/YDkyiDXU4ar/dja0FDE2r7jsN9D+FfW49+iDvXr4ELQyhZpW3Zr1Ojwm58
  > CJzjZwbRYiVwPBRsKmiYfO1E7esvw3CmjK5chfz8c40f6/APDro9ZmYNBRv2CnJy
  > t/DtcM/GpAhBbLP9Tk7kPB41v5fRIxVDo50Iz/qvkr37pQ4RsejSFg==
  > -----END CERTIFICATE-----
  > EOF

Dump a SPIFFE example certificate (example-spiffe.crt) to JSON output

  $ certigo dump --json example-spiffe.crt
  {"certificates":[{"serial":"4096","not_before":"2017-07-19T16:50:20Z","not_after":"2017-07-29T16:50:20Z","signature_algorithm":"SHA256-RSA","is_self_signed":false,"subject":{"common_name":"blog","country":["US"],"key_id":"55:43:DD:63:48:E3:8D:CD:5A:F5:54:60:5D:24:E9:4F:37:ED:D7:C5","organization":["test1.acme.com"]},"issuer":{"common_name":"IntermediaetCA","country":["US"],"key_id":"35:DD:B7:F1:E7:4A:C3:64:ED:F2:D8:26:5D:1C:F8:25:78:55:04:A0","organization":["test1.acme.com"]},"basic_constraints":{"is_ca":false},"key_usage":["Digital Signature","Key Encipherment","Key Agreement"],"extended_key_usage":["Server Auth"],"uri_names":["spiffe://dev.acme.com/path/service"],"warnings":["[CABF_BR] DNSNames should not contain a bare IANA suffix.","[CABF_BR] Subscriber Certificate: authorityInformationAccess MUST be present.","[CABF_BR] Subscriber Certificate: authorityInformationAccess MUST contain the HTTP URL of the Issuing CA's OSCP responder.","[CABF_BR] Subscriber Certificate: certificatePolicies MUST be present and SHOULD NOT be marked critical.","[CABF_BR] Subscriber Certificate: subject:localityName MUST appear if subject:organizationName, subject:givenName, or subject:surname fields are present but the subject:stateOrProvinceName field is absent.","[CABF_BR] Subscriber Certificate: subject:stateOrProvinceName MUST appear if the subject:organizationName, subject:givenName, or subject:surname fields are present and subject:localityName is absent.","[CABF_BR] Subscriber certificates authorityInformationAccess extension should contain the HTTP URL of the issuing CA’s certificate","[CABF_BR] Subscriber certificates must contain at least one policy identifier that indicates adherence to CAB standards","[CABF_BR] The Subject Alternate Name extension MUST contain only 'dnsName' and 'ipaddress' name types","[CABF_BR] The common name field in subscriber certificates must include only names from the SAN extension"],"pem":"-----BEGIN CERTIFICATE-----\nMIIE1DCCArygAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwPzELMAkGA1UEBhMCVVMx\nFzAVBgNVBAoMDnRlc3QxLmFjbWUuY29tMRcwFQYDVQQDDA5JbnRlcm1lZGlhZXRD\nQTAeFw0xNzA3MTkxNjUwMjBaFw0xNzA3MjkxNjUwMjBaMDUxCzAJBgNVBAYTAlVT\nMRcwFQYDVQQKDA50ZXN0MS5hY21lLmNvbTENMAsGA1UEAwwEYmxvZzCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKm8P47lABp4+rz2nN+QYrxedbaFVWoF\nFuoSkqcHsafMwbMrN+kI6wJVtlbwviDvxWFJ92q0H71QNFybTsmof3KUN/kYCp7P\n+LKhBrN0ttWI5q6v5eDrjN0VdtVdnlZOYmJFbvETOgfK/qXKNRRM8HYW0tdqrtEw\nCR5dIu53xVUSViBdwXpuy2c5W2mFn1gxTpdW+3hbZsL1pHrU9qPWLtTgl/KY8kjs\nI7KW1cIcinE4SJomhB5L/4emhxKGY+kEa2+fN9IPjjvKSMOw9kiBKk1GHZcIY5EA\nO3TIfUk3fysPzi5qA0su/bNtPQy1uXgXS10xUlV7pqRPvHjiNzgFkXUCAwEAAaOB\n4zCB4DAJBgNVHRMEAjAAMB0GA1UdDgQWBBRVQ91jSOONzVr1VGBdJOlPN+3XxTBg\nBgNVHSMEWTBXgBQ13bfx50rDZO3y2CZdHPgleFUEoKE7pDkwNzELMAkGA1UEBhMC\nVVMxFzAVBgNVBAoMDnRlc3QxLmFjbWUuY29tMQ8wDQYDVQQDDAZSb290Q0GCAhAA\nMA4GA1UdDwEB/wQEAwIDqDATBgNVHSUEDDAKBggrBgEFBQcDATAtBgNVHREEJjAk\nhiJzcGlmZmU6Ly9kZXYuYWNtZS5jb20vcGF0aC9zZXJ2aWNlMA0GCSqGSIb3DQEB\nCwUAA4ICAQBp2+rtUxt1VmNM/vi6PwoSoYzWFmQ2nc4OM7bsOG4uppU54wRYZ+T7\nc42EcrpyBgWn+rWHT1Hi6SNcmloKHydaUTZ4pq3IlKKnBNqwivU5BzIxYLDrhR/U\nwd9s1tgmLvADqkQa1XjjSFn5Auoj1R640ry4qpw8IOusdm6wVhru4ssRnHX4E2uR\njQe7b3ws38aZhjtL78Ip0BB4yPxWJRp/WmEoT33QP+cZhA4IYWECxNODr6DSJeq2\nVNu/6JACGrNfM2Sjt4Wxz+nIa3cKDNCA6PR8StTUTcoQ6ZBzpn+n/Q1xSRIOJz6N\nhgfkyb9O7HAMdAP+TxehjqG3gh5Ky2DgYMCIZOztVzsuOb1DGJe/kGUKeRJLl2/O\nQwkctwUOcVIxckNu6OvclriFzvoXObqO77XeCI2V1Vef0wGTWlWNOdbFa4708Y7f\n5UdwInYQUi87RFDnc1SDU4Jrsv4KzZiv9FCfDg8pCBIdWpWT7DAuI0d7i7PZ+iFt\nZZ6sb/YDkyiDXU4ar/dja0FDE2r7jsN9D+FfW49+iDvXr4ELQyhZpW3Zr1Ojwm58\nCJzjZwbRYiVwPBRsKmiYfO1E7esvw3CmjK5chfz8c40f6/APDro9ZmYNBRv2CnJy\nt/DtcM/GpAhBbLP9Tk7kPB41v5fRIxVDo50Iz/qvkr37pQ4RsejSFg==\n-----END CERTIFICATE-----\n"}]}
