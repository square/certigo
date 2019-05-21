/*-
 * Copyright 2017 Square Inc.
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

package starttls

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
)

func dumpAuthTLSFromIMAP(dialer Dialer, address string, config *tls.Config) (*tls.ConnectionState, error) {
	c, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, err
	}

	conn := c.(*net.TCPConn)
	status, err := readIMAP(conn)
	if err != nil {
		return nil, err
	}
	if status != "OK" {
		return nil, fmt.Errorf("IMAP server responded with %s, was expecting OK", status)
	}

	fmt.Fprintf(conn, "1 STARTTLS\r\n")
	status, err = readIMAP(conn)
	if err != nil {
		return nil, err
	}
	if status != "OK" {
		return nil, fmt.Errorf("IMAP server responded with %s, was expecting OK", status)
	}

	tlsConn := tls.Client(conn, config)
	err = tlsConn.Handshake()
	if err != nil {
		return nil, err
	}

	state := tlsConn.ConnectionState()
	return &state, nil
}

func readIMAP(conn *net.TCPConn) (string, error) {
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return response[2:4], nil
}
