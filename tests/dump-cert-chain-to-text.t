Set up test data.

  $ cat > squareup-chain.crt <<EOF
  > -----BEGIN CERTIFICATE-----
  > MIIHnjCCBoagAwIBAgIRAMQdTn1Z7px7AAAAAFTMznkwDQYJKoZIhvcNAQELBQAw
  > gboxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1FbnRydXN0LCBJbmMuMSgwJgYDVQQL
  > Ex9TZWUgd3d3LmVudHJ1c3QubmV0L2xlZ2FsLXRlcm1zMTkwNwYDVQQLEzAoYykg
  > MjAxNCBFbnRydXN0LCBJbmMuIC0gZm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxLjAs
  > BgNVBAMTJUVudHJ1c3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBMMU0wHhcN
  > MTYwNzE1MjAxNTUyWhcNMTcwNzMxMjA0NTUwWjCBzTELMAkGA1UEBhMCVVMxEzAR
  > BgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xEzARBgsr
  > BgEEAYI3PAIBAxMCVVMxGTAXBgsrBgEEAYI3PAIBAhMIRGVsYXdhcmUxFTATBgNV
  > BAoTDFNxdWFyZSwgSW5jLjEdMBsGA1UEDxMUUHJpdmF0ZSBPcmdhbml6YXRpb24x
  > EDAOBgNVBAUTBzQ2OTk4NTUxGTAXBgNVBAMTEHd3dy5zcXVhcmV1cC5jb20wggEi
  > MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDk+qX7IYPlzj+SJijzKDSOEh5x
  > LDyVq6N8k+5bgSISr9pXbhJB2yFDsvzHn+s67B5x2jjwUfvvMYnS8Aad73UqeVJQ
  > 5zPhLh9TL0U6ltgVUbKeVvxcZlGVj34WgqDJL3rMAEAJzDPZJ/Td/GNBWtrDOpdZ
  > GQoNwdf/xK26ep/RKiqJWjCDBVd8Grxq0xqxaNvdml6mMJS49s5Ku5e5kvHwq7E7
  > sVX79h1k3IfYgPM5VFU0CLxBVwXwg2eQrDxxbQbgqf+am5vBaEB0olCIPrp4WImv
  > 2B5cQa5/9AjXihCusXmyvDp0UBZOoFy1D6La1eJyMxgUK3uj2C+Z2DkdpythAgMB
  > AAGjggOIMIIDhDCBmgYDVR0RBIGSMIGPghB3d3cuc3F1YXJldXAuY29tggxzcXVh
  > cmV1cC5jb22CFGFjY291bnQuc3F1YXJldXAuY29tggdta3QuY29tggt3d3cubWt0
  > LmNvbYITbWFya2V0LnNxdWFyZXVwLmNvbYIIZ29zcS5jb22CDHd3dy5nb3NxLmNv
  > bYIHZ29zcS5jb4ILd3d3Lmdvc3EuY28wggF+BgorBgEEAdZ5AgQCBIIBbgSCAWoB
  > aAB2AGj2mPgfZIK+OozuuSgdTPxxUV1nk9RE0QpnrLtPT/vEAAABVfBO8foAAAQD
  > AEcwRQIgHRuE49MQdG9gn47iHetv5bNzKLcaP9uReKBa/0c7luECIQCE/Km4MXBr
  > 1fTTezjnGD5ZTxdcfnuStsy2FejS0ldWUQB2AFYUBpov18Ls0/XhvUSyPsdGdrm8
  > mRFcwO+UmFXWidDdAAABVfBO9scAAAQDAEcwRQIgWG3bnNz07rT7yjGdjvCC6F9i
  > aiBxsWpnLmYxc0ycrogCIQD7a1RbCM8o+bGbTRmpZv9Z5M6beO+eoC/TXDFZdK58
  > JAB2AKS5CZC0GFgUh7sTosxncAo8NZgE+RvfuON3zQ7IDdwQAAABVfBO+BQAAAQD
  > AEcwRQIgVmnuQ6nwHIwGcXRAqXVvqAQJkdzbe5DpCYM/e5FD15wCIQCdGxXNam6p
  > xblJX2oUnPdsxfUvP++u94bgKgJDUdDMgDAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0l
  > BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMGgGCCsGAQUFBwEBBFwwWjAjBggrBgEF
  > BQcwAYYXaHR0cDovL29jc3AuZW50cnVzdC5uZXQwMwYIKwYBBQUHMAKGJ2h0dHA6
  > Ly9haWEuZW50cnVzdC5uZXQvbDFtLWNoYWluMjU2LmNlcjAzBgNVHR8ELDAqMCig
  > JqAkhiJodHRwOi8vY3JsLmVudHJ1c3QubmV0L2xldmVsMW0uY3JsMEoGA1UdIARD
  > MEEwNgYKYIZIAYb6bAoBAjAoMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LmVudHJ1
  > c3QubmV0L3JwYTAHBgVngQwBATAfBgNVHSMEGDAWgBTD99C1KjCtrw2RIXA5VN28
  > iXDHOjAdBgNVHQ4EFgQU1BcUbwvFIKHW/iF+3J74V5ztrmowCQYDVR0TBAIwADAN
  > BgkqhkiG9w0BAQsFAAOCAQEAhb0ixKT20fiDn+0tjAM/WeqQZpQRyQFT1jIK8ERI
  > HsTeEV291SiLaatV6laocpx7R/JgwAQc1bPItf3HguhetWeXSTFDBQyy4InN0ceB
  > RQJDPl6gcmq9xC9KMgMgXmh0FDrG2yMHRC3Qz9dSPDTPTNrCjLvW1PPK0o1pQ9cz
  > ISdRtVnLz6/3tkx/bUNkT1TQ6mpslx5CBqyZS8LHzLr13Ei8D5P6RhsKXT6JS3Ki
  > G2TfXmg9UFgsiNho7aRpLhyI66wNB+akENKPk0n23RkxpYkRtIcFUY9LIYBbvGHT
  > Qq1IhY7LwcjCwcGePa0CtcnnwrA6jPnlEpTR6bh1NW5IaA==
  > -----END CERTIFICATE-----
  > -----BEGIN CERTIFICATE-----
  > MIIFLTCCBBWgAwIBAgIMYaHn0gAAAABR02amMA0GCSqGSIb3DQEBCwUAMIG+MQsw
  > CQYDVQQGEwJVUzEWMBQGA1UEChMNRW50cnVzdCwgSW5jLjEoMCYGA1UECxMfU2Vl
  > IHd3dy5lbnRydXN0Lm5ldC9sZWdhbC10ZXJtczE5MDcGA1UECxMwKGMpIDIwMDkg
  > RW50cnVzdCwgSW5jLiAtIGZvciBhdXRob3JpemVkIHVzZSBvbmx5MTIwMAYDVQQD
  > EylFbnRydXN0IFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHMjAeFw0x
  > NDEyMTUxNTI1MDNaFw0zMDEwMTUxNTU1MDNaMIG6MQswCQYDVQQGEwJVUzEWMBQG
  > A1UEChMNRW50cnVzdCwgSW5jLjEoMCYGA1UECxMfU2VlIHd3dy5lbnRydXN0Lm5l
  > dC9sZWdhbC10ZXJtczE5MDcGA1UECxMwKGMpIDIwMTQgRW50cnVzdCwgSW5jLiAt
  > IGZvciBhdXRob3JpemVkIHVzZSBvbmx5MS4wLAYDVQQDEyVFbnRydXN0IENlcnRp
  > ZmljYXRpb24gQXV0aG9yaXR5IC0gTDFNMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
  > MIIBCgKCAQEA0IHBOSPCsdHs91fdVSQ2kSAiSPf8ylIKsKs/M7WwhAf23056sPuY
  > Ij0BrFb7cW2y7rmgD1J3q5iTvjOK64dex6qwymmPQwhqPyK/MzlG1ZTy4kwFItln
  > gJHxBEoOm3yiydJs/TwJhL39axSagR3nioPvYRZ1R5gTOw2QFpi/iuInMlOZmcP7
  > lhw192LtjL1JcdJDQ6Gh4yEqI3CodT2ybEYGYW8YZ+QpfrI8wcVfCR5uRE7sIZlY
  > FUj0VUgqtzS0BeN8SYwAWN46lsw53GEzVc4qLj/RmWLoquY0djGqr3kplnjLgRSv
  > adr7BLlZg0SqCU+01CwBnZuUMWstoc/B5QIDAQABo4IBKzCCAScwDgYDVR0PAQH/
  > BAQDAgEGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATASBgNVHRMBAf8E
  > CDAGAQH/AgEAMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29j
  > c3AuZW50cnVzdC5uZXQwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL2NybC5lbnRy
  > dXN0Lm5ldC9nMmNhLmNybDA7BgNVHSAENDAyMDAGBFUdIAAwKDAmBggrBgEFBQcC
  > ARYaaHR0cDovL3d3dy5lbnRydXN0Lm5ldC9ycGEwHQYDVR0OBBYEFMP30LUqMK2v
  > DZEhcDlU3byJcMc6MB8GA1UdIwQYMBaAFGpyJnrQHu995ztpUdRsjZ+QEmarMA0G
  > CSqGSIb3DQEBCwUAA4IBAQC0h8eEIhopwKR47PVPG7SEl2937tTPWa+oQ5YvHVje
  > pvMVWy7ZQ5xMQrkXFxGttLFBx2YMIoYFp7Qi+8VoaIqIMthx1hGOjlJ+Qgld2dnA
  > DizvRGsf2yS89byxqsGK5Wbb0CTz34mmi/5e0FC6m3UAyQhKS3Q/WFOv9rihbISY
  > Jnz8/DVRZZgeO2x28JkPxLkJ1YXYJKd/KsLak0tkuHB8VCnTglTVz6WUwzOeTTRn
  > 4Dh2ZgCN0C/GqwmqcvrOLzWJ/MDtBgO334wlV/H77yiI2YIowAQPlIFpI+CRKMVe
  > 1QzX1CA778n4wI+nQc1XRG5sZ2L+hN/nYNjvv9QiHg3n
  > -----END CERTIFICATE-----
  > -----BEGIN CERTIFICATE-----
  > MIIE/zCCA+egAwIBAgIEUdNARDANBgkqhkiG9w0BAQsFADCBsDELMAkGA1UEBhMC
  > VVMxFjAUBgNVBAoTDUVudHJ1c3QsIEluYy4xOTA3BgNVBAsTMHd3dy5lbnRydXN0
  > Lm5ldC9DUFMgaXMgaW5jb3Jwb3JhdGVkIGJ5IHJlZmVyZW5jZTEfMB0GA1UECxMW
  > KGMpIDIwMDYgRW50cnVzdCwgSW5jLjEtMCsGA1UEAxMkRW50cnVzdCBSb290IENl
  > cnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE0MDkyMjE3MTQ1N1oXDTI0MDkyMzAx
  > MzE1M1owgb4xCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1FbnRydXN0LCBJbmMuMSgw
  > JgYDVQQLEx9TZWUgd3d3LmVudHJ1c3QubmV0L2xlZ2FsLXRlcm1zMTkwNwYDVQQL
  > EzAoYykgMjAwOSBFbnRydXN0LCBJbmMuIC0gZm9yIGF1dGhvcml6ZWQgdXNlIG9u
  > bHkxMjAwBgNVBAMTKUVudHJ1c3QgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0
  > eSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuoS2ctueDGvi
  > mekwAad26jK4lUEaydphTlhyz/72gnm/c2EGCqUn2LNf00VOHHLWTjLycooP94MZ
  > 0GqAgABFHrDH55q/ElcnHKNoLwqHvWprDl5l8xx31dSFjXAhtLMy54ui1YY5ArG4
  > 0kfO5MlJxDun3vtUfVe+8OhuwnmyOgtV4lCYFjITXC94VsHClLPyWuQnmp8k18bs
  > 0JslguPMwsRFxYyXegZrKhGfqQpuSDtv29QRGUL3jwe/9VNfnD70FyzmaaxOMkxi
  > d+q36OW7NLwZi66cUee3frVTsTMi5W3PcDwa+uKbZ7aD9I2lr2JMTeBYrGQ0EgP4
  > to2UYySkcQIDAQABo4IBDzCCAQswDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQI
  > MAYBAf8CAQEwMwYIKwYBBQUHAQEEJzAlMCMGCCsGAQUFBzABhhdodHRwOi8vb2Nz
  > cC5lbnRydXN0Lm5ldDAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3JsLmVudHJ1
  > c3QubmV0L3Jvb3RjYTEuY3JsMDsGA1UdIAQ0MDIwMAYEVR0gADAoMCYGCCsGAQUF
  > BwIBFhpodHRwOi8vd3d3LmVudHJ1c3QubmV0L0NQUzAdBgNVHQ4EFgQUanImetAe
  > 733nO2lR1GyNn5ASZqswHwYDVR0jBBgwFoAUaJDkZ6SmU4DHhmak8fdLQ/uEvW0w
  > DQYJKoZIhvcNAQELBQADggEBAGkzg/woem99751V68U+ep11s8zDODbZNKIoaBjq
  > HmnTvefQd9q4AINOSs9v0fHBIj905PeYSZ6btp7h25h3LVY0sag82f3Azce/BQPU
  > AsXx5cbaCKUTx2IjEdFhMB1ghEXveajGJpOkt800uGnFE/aRs8lFc3a2kvZ2Clvh
  > A0e36SlMkTIjN0qcNdh4/R0f5IOJJICtt/nP5F2l1HHEhVtwH9s/HAHrGkUmMRTM
  > Zb9n3srMM2XlQZHXN75BGpad5oqXnafOrE6aPb0BoGrZTyIAi0TVaWJ7LuvMuueS
  > fWlnPfy4fN5Bh9Bp6roKGHoalUOzeXEodm2h+1dK7E3IDhA=
  > -----END CERTIFICATE-----
  > EOF

Dump a live cert chain (squareup-chain.crt)

  $ certigo --verbose dump squareup-chain.crt
  ** CERTIFICATE 1 **
  Input Format: PEM
  Serial: 260680855742043049380997676879525498489
  Valid: 2016-07-15 20:15 UTC to 2017-07-31 20:45 UTC
  Signature: SHA256-RSA
  Subject Info:
  \tCountry: US (esc)
  \tProvince: California (esc)
  \tLocality: San Francisco (esc)
  \tEV Incorporation Country: US (esc)
  \tEV Incorporation Province: Delaware (esc)
  \tOrganization: Square, Inc. (esc)
  \tBusiness Category: Private Organization (esc)
  \tEV Incorporation Registration Number: 4699855 (esc)
  \tCommonName: www.squareup.com (esc)
  Issuer Info:
  \tCountry: US (esc)
  \tOrganization: Entrust, Inc. (esc)
  \tOrganizational Unit: See www.entrust.net/legal-terms (esc)
  \tOrganizational Unit: (c) 2014 Entrust, Inc. - for authorized use only (esc)
  \tCommonName: Entrust Certification Authority - L1M (esc)
  Subject Key ID: D4:17:14:6F:0B:C5:20:A1:D6:FE:21:7E:DC:9E:F8:57:9C:ED:AE:6A
  Authority Key ID: C3:F7:D0:B5:2A:30:AD:AF:0D:91:21:70:39:54:DD:BC:89:70:C7:3A
  Basic Constraints: CA:false
  OCSP Server(s):
  \thttp://ocsp.entrust.net (esc)
  Issuing Certificate URL(s):
  \thttp://aia.entrust.net/l1m-chain256.cer (esc)
  Key Usage:
  \tDigital Signature (esc)
  \tKey Encipherment (esc)
  Extended Key Usage:
  \tServer Auth (esc)
  \tClient Auth (esc)
  DNS Names:
  \twww.squareup.com, squareup.com, (esc)
  \taccount.squareup.com, mkt.com, www.mkt.com, (esc)
  \tmarket.squareup.com, gosq.com, www.gosq.com, (esc)
  \tgosq.co, www.gosq.co (esc)
  Signed Certificate Timestamp:
  \tVersion: 0 (v1) (esc)
  \tLog Operator: Google (esc)
  \tLog URL: https://ct.googleapis.com/aviator/ (esc)
  \tLog ID: 68:F6:98:F8:1F:64:82:BE:3A:8C:EE:B9:28:1D:4C:FC: (esc)
  \t        71:51:5D:67:93:D4:44:D1:0A:67:AC:BB:4F:4F:FB:C4 (esc)
  \tTimestamp: 2016-07-15 20:45 GMT (esc)
  \tSignature: ECDSA-SHA256 (esc)
  Signed Certificate Timestamp:
  \tVersion: 0 (v1) (esc)
  \tLog Operator: DigiCert (esc)
  \tLog URL: https://ct1.digicert-ct.com/log/ (esc)
  \tLog ID: 56:14:06:9A:2F:D7:C2:EC:D3:F5:E1:BD:44:B2:3E:C7: (esc)
  \t        46:76:B9:BC:99:11:5C:C0:EF:94:98:55:D6:89:D0:DD (esc)
  \tTimestamp: 2016-07-15 20:45 GMT (esc)
  \tSignature: ECDSA-SHA256 (esc)
  Signed Certificate Timestamp:
  \tVersion: 0 (v1) (esc)
  \tLog Operator: Google (esc)
  \tLog URL: https://ct.googleapis.com/pilot/ (esc)
  \tLog ID: A4:B9:09:90:B4:18:58:14:87:BB:13:A2:CC:67:70:0A: (esc)
  \t        3C:35:98:04:F9:1B:DF:B8:E3:77:CD:0E:C8:0D:DC:10 (esc)
  \tTimestamp: 2016-07-15 20:45 GMT (esc)
  \tSignature: ECDSA-SHA256 (esc)
  
  ** CERTIFICATE 2 **
  Input Format: PEM
  Serial: 30215777750102225331854468774
  Valid: 2014-12-15 15:25 UTC to 2030-10-15 15:55 UTC
  Signature: SHA256-RSA
  Subject Info:
  \tCountry: US (esc)
  \tOrganization: Entrust, Inc. (esc)
  \tOrganizational Unit: See www.entrust.net/legal-terms (esc)
  \tOrganizational Unit: (c) 2014 Entrust, Inc. - for authorized use only (esc)
  \tCommonName: Entrust Certification Authority - L1M (esc)
  Issuer Info:
  \tCountry: US (esc)
  \tOrganization: Entrust, Inc. (esc)
  \tOrganizational Unit: See www.entrust.net/legal-terms (esc)
  \tOrganizational Unit: (c) 2009 Entrust, Inc. - for authorized use only (esc)
  \tCommonName: Entrust Root Certification Authority - G2 (esc)
  Subject Key ID: C3:F7:D0:B5:2A:30:AD:AF:0D:91:21:70:39:54:DD:BC:89:70:C7:3A
  Authority Key ID: 6A:72:26:7A:D0:1E:EF:7D:E7:3B:69:51:D4:6C:8D:9F:90:12:66:AB
  Basic Constraints: CA:true, pathlen:0
  OCSP Server(s):
  \thttp://ocsp.entrust.net (esc)
  Key Usage:
  \tCert Sign (esc)
  \tCRL Sign (esc)
  Extended Key Usage:
  \tClient Auth (esc)
  \tServer Auth (esc)
  Warnings:
  \t[w_sub_ca_aia_does_not_contain_issuing_ca_url]  (esc)
  
  ** CERTIFICATE 3 **
  Input Format: PEM
  Serial: 1372799044
  Valid: 2014-09-22 17:14 UTC to 2024-09-23 01:31 UTC
  Signature: SHA256-RSA
  Subject Info:
  \tCountry: US (esc)
  \tOrganization: Entrust, Inc. (esc)
  \tOrganizational Unit: See www.entrust.net/legal-terms (esc)
  \tOrganizational Unit: (c) 2009 Entrust, Inc. - for authorized use only (esc)
  \tCommonName: Entrust Root Certification Authority - G2 (esc)
  Issuer Info:
  \tCountry: US (esc)
  \tOrganization: Entrust, Inc. (esc)
  \tOrganizational Unit: www.entrust.net/CPS is incorporated by reference (esc)
  \tOrganizational Unit: (c) 2006 Entrust, Inc. (esc)
  \tCommonName: Entrust Root Certification Authority (esc)
  Subject Key ID: 6A:72:26:7A:D0:1E:EF:7D:E7:3B:69:51:D4:6C:8D:9F:90:12:66:AB
  Authority Key ID: 68:90:E4:67:A4:A6:53:80:C7:86:66:A4:F1:F7:4B:43:FB:84:BD:6D
  Basic Constraints: CA:true, pathlen:1
  OCSP Server(s):
  \thttp://ocsp.entrust.net (esc)
  Key Usage:
  \tCert Sign (esc)
  \tCRL Sign (esc)
  Warnings:
  \t[w_sub_ca_aia_does_not_contain_issuing_ca_url]  (esc)