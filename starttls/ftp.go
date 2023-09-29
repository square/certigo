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
	"strconv"
)

type FTPCtx struct {
	tcpConn  *net.TCPConn
	tlsConn  *tls.Conn
	dialFunc func(dialer Dialer, address string) (net.Conn, error)
}

func dumpTLSConnStateFromFTP(dialer Dialer, address string, config *tls.Config, explicitTLS bool) (*tls.ConnectionState, error) {

	ctx := FTPCtx{}

	if explicitTLS {
		ctx.dialFunc = func(dialer Dialer, address string) (net.Conn, error) {
			return dialer.Dial("tcp", address)
		}
	} else {
		ctx.dialFunc = func(dialer Dialer, address string) (net.Conn, error) {
			tlsDialer := &tls.Dialer{
				NetDialer: dialer.(*net.Dialer),
				Config:    config,
			}
			return tlsDialer.Dial("tcp", address)
		}
	}

	c, err := ctx.dialFunc(dialer, address)
	if err != nil {
		return nil, err
	}

	if _, err = checkServiceReady(c); err != nil {
		return nil, err
	}

	if explicitTLS {
		ctx.tcpConn = c.(*net.TCPConn)
	} else {
		ctx.tlsConn = c.(*tls.Conn)
	}

	if explicitTLS {
		if _, err := authTLS(ctx.tcpConn); err != nil {
			return nil, err
		}
		ctx.tlsConn = tls.Client(ctx.tcpConn, config)
		ctx.tlsConn.Handshake()
	}

	state := ctx.tlsConn.ConnectionState()
	return &state, nil
}

func checkServiceReady(conn net.Conn) (int, error) {
	status, err := readFTP(conn)
	if err != nil {
		return status, err
	}
	if status != 220 {
		return status, fmt.Errorf("FTP server responded with status %d, was expecting 220", status)
	}
	return status, nil
}

func authTLS(conn *net.TCPConn) (int, error) {
	fmt.Fprintf(conn, "AUTH TLS\r\n")
	status, err := readFTP(conn)
	if err != nil {
		return status, err
	}
	if status != 234 {
		return status, fmt.Errorf("FTP server responded with status %d, was expecting 234", status)
	}
	return status, nil
}

func readFTP(conn net.Conn) (int, error) {
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}
	if len(response) <= 3 {
		return 0, fmt.Errorf("Error parsing ftp protocol: Status code too short: '%s'", response)
	}
	return strconv.Atoi(response[:3])
}
