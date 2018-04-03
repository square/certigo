/*-
 * Copyright 2018 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/ocsp"
)

var (
	skippedRevocationCheck = errors.New("skipped revocation check")
)

func checkOCSP(chain []*x509.Certificate, ocspStaple []byte) (status *ocsp.Response, err error) {
	if len(chain) <= 1 {
		// Nothing to check here
		return nil, skippedRevocationCheck
	}

	encoded := ocspStaple
	if len(encoded) == 0 {
		encoded, err = fetchOCSP(chain)
		if err != nil {
			return nil, err
		}
	}

	status, err = ocsp.ParseResponse(encoded, chain[1])
	if err != nil {
		return nil, fmt.Errorf("bad OCSP status: %s", err)
	}

	return status, err
}

func fetchOCSP(chain []*x509.Certificate) ([]byte, error) {
	var lastError error
	for _, issuer := range chain[1:] {
		encoded, err := ocsp.CreateRequest(chain[0], issuer, nil)
		if err != nil {
			return nil, fmt.Errorf("failure building request: %s", err)
		}

		// Try all the OCSP servers listed in the certificate
		for _, server := range issuer.OCSPServer {
			// We try both GET and POST requests, because some servers are janky.
			reqs := []*http.Request{}
			if len(encoded) < 255 {
				// GET only supported if we can stash the OCSP request into the path
				req, err := buildOCSPwithGET(server, encoded)
				if err != nil {
					lastError = err
					continue
				}
				reqs = append(reqs, req)
			}

			// POST should always be supported, but some servers don't like it
			req, err := buildOCSPwithPOST(server, encoded)
			if err != nil {
				lastError = err
				continue
			}
			reqs = append(reqs, req)

			for _, req := range reqs {
				resp, err := (&http.Client{}).Do(req)
				if err != nil {
					lastError = err
					continue
				}

				if resp.StatusCode != http.StatusOK {
					lastError = fmt.Errorf("unexpected status code, got: %s", resp.Status)
					continue
				}

				body, err := ioutil.ReadAll(resp.Body)
				defer resp.Body.Close()
				if err != nil {
					lastError = err
					continue
				}

				return body, nil
			}
		}
	}

	return nil, lastError
}

func buildOCSPwithPOST(server string, encoded []byte) (*http.Request, error) {
	req, err := http.NewRequest("POST", server, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/ocsp-request")
	req.Header.Add("Accept", "application/ocsp-response")
	req.Write(bytes.NewBuffer(encoded))

	return req, nil
}

func buildOCSPwithGET(server string, encoded []byte) (*http.Request, error) {
	if !strings.HasSuffix(server, "/") {
		server = server + "/"
	}

	base, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	// Note that this is *not* url-safe base64 encoding, so we escape
	path, err := url.Parse(url.PathEscape(base64.StdEncoding.EncodeToString(encoded)))
	if err != nil {
		return nil, err
	}

	uri := base.ResolveReference(path)
	req, err := http.NewRequest("GET", uri.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/ocsp-response")

	return req, nil
}
