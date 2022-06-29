package lib

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctutil "github.com/google/certificate-transparency-go/x509util"
)

// https://github.com/google/certificate-transparency-community-site/blob/master/docs/google/known-logs.md
const knownLogsAddr = "https://www.gstatic.com/ct/log_list/v2/log_list.json"

var (
	knownLogs     map[string]*ctLog
	knownLogsOnce sync.Once
)

type ctLog struct {
	operator string
	url      string
}

func parseSCTList(cert *x509.Certificate) []*simpleSCT {
	// ctutil contains a fork of crypto/x509 with support for SCTs. We must re-parse the
	// whole certificate to get at them, so do a quick check to see if the SCT extension
	// is present before re-parsing the cert unnecessarily.
	if !hasSCTs(cert) {
		return nil
	}

	var sctList []*simpleSCT
	if scts, err := ctutil.ParseSCTsFromCertificate(cert.Raw); err == nil {
		for _, sct := range scts {
			id := sct.LogID.KeyID[:]
			ssct := &simpleSCT{
				Version:            uint64(sct.SCTVersion),
				LogID:              id,
				Timestamp:          time.UnixMilli(int64(sct.Timestamp)),
				SignatureAlgorithm: sctSignatureAlg(sct.Signature.Algorithm),
			}
			if log := getLogByID(id); log != nil {
				ssct.LogOperator = log.operator
				ssct.LogURL = log.url
			}
			sctList = append(sctList, ssct)
		}
	}
	return sctList
}

func hasSCTs(cert *x509.Certificate) bool {
	for _, e := range cert.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier(ctx509.OIDExtensionCTSCT)) {
			return true
		}
	}
	return false
}

func getLogByID(id []byte) *ctLog {
	knownLogsOnce.Do(func() {
		client := &http.Client{
			// Set a timeout so we don't block forever on broken servers.
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(knownLogsAddr)
		if err != nil {
			log.Printf("Failed to fetch the list of known CT logs: %v", err)
			return
		}
		defer resp.Body.Close()

		var logs struct {
			Operators []struct {
				Name string `json:"name"`
				Logs []struct {
					ID  string `json:"log_id"`
					URL string `json:"url"`
				} `json:"logs"`
			} `json:"operators"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
			log.Printf("Failed to parse the list of known CT logs: %v", err)
			return
		}

		knownLogs = make(map[string]*ctLog)
		for _, op := range logs.Operators {
			for _, l := range op.Logs {
				knownLogs[l.ID] = &ctLog{
					operator: op.Name,
					url:      l.URL,
				}
			}
		}
	})
	b64 := base64.StdEncoding.EncodeToString(id)
	return knownLogs[b64]
}

func sctSignatureAlg(alg cttls.SignatureAndHashAlgorithm) simpleSigAlg {
	x509Alg := x509.UnknownSignatureAlgorithm
	switch alg.Signature {
	case cttls.RSA:
		switch alg.Hash {
		case cttls.MD5:
			x509Alg = x509.MD5WithRSA
		case cttls.SHA1:
			x509Alg = x509.SHA1WithRSA
		case cttls.SHA256:
			x509Alg = x509.SHA256WithRSA
		case cttls.SHA384:
			x509Alg = x509.SHA384WithRSA
		case cttls.SHA512:
			x509Alg = x509.SHA512WithRSA
		}
	case cttls.DSA:
		switch alg.Hash {
		case cttls.SHA1:
			x509Alg = x509.DSAWithSHA1
		case cttls.SHA256:
			x509Alg = x509.DSAWithSHA256
		}
	case cttls.ECDSA:
		switch alg.Hash {
		case cttls.SHA1:
			x509Alg = x509.ECDSAWithSHA1
		case cttls.SHA256:
			x509Alg = x509.ECDSAWithSHA256
		case cttls.SHA384:
			x509Alg = x509.ECDSAWithSHA384
		case cttls.SHA512:
			x509Alg = x509.ECDSAWithSHA512
		}
	}
	return simpleSigAlg(x509Alg)
}
