// Copyright 2025 Block, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"log"
	"maps"
	"net/http"
	"os"
	"slices"
	"strconv"
)

var (
	out = flag.String("out", "", "Output file")
)

// https://github.com/google/certificate-transparency-community-site/blob/master/docs/google/known-logs.md
//
// The v3 list includes static-ct-api ("tiled") logs, but drops logs once they
// expire, so logs that are no longer listed are kept from the existing output.
const knownLogsAddr = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"

type ctLog struct {
	operator string
	url      string
}

// logList is the part of the v3 log list that certigo uses.
type logList struct {
	Version   string `json:"version"`
	Timestamp string `json:"log_list_timestamp"`
	Operators []struct {
		Name string `json:"name"`
		Logs []struct {
			ID  string `json:"log_id"`
			URL string `json:"url"`
		} `json:"logs"`
		TiledLogs []struct {
			ID            string `json:"log_id"`
			SubmissionURL string `json:"submission_url"`
		} `json:"tiled_logs"`
	} `json:"operators"`
}

func main() {
	flag.Parse()

	list, err := fetchLogList(knownLogsAddr)
	if err != nil {
		log.Fatalf("Failed to fetch the list of known CT logs: %v", err)
	}

	// Keep logs from the existing output that are no longer listed, so that
	// SCTs in older certificates still show their log operator.
	logs, err := readKnownLogs(*out)
	if err != nil {
		log.Fatalf("Failed to read known CT logs from %s: %v", *out, err)
	}
	maps.Copy(logs, list.knownLogs())

	f, err := os.Create(*out)
	if err != nil {
		log.Fatalf("Failed to open file %s: %v", *out, err)
	}
	if err := writeKnownLogs(f, os.Getenv("GOPACKAGE"), list, logs); err != nil {
		log.Fatalf("Failed to write %s: %v", *out, err)
	}
	if err := f.Close(); err != nil {
		log.Fatalf("Failed to write %s: %v", *out, err)
	}
}

func fetchLogList(addr string) (*logList, error) {
	resp, err := http.Get(addr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", addr, resp.Status)
	}

	var list logList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", addr, err)
	}
	return &list, nil
}

// knownLogs returns the logs in the list by base64 log ID. A tiled log's URL
// is its submission URL.
func (l *logList) knownLogs() map[string]ctLog {
	logs := make(map[string]ctLog)
	for _, op := range l.Operators {
		for _, cl := range op.Logs {
			logs[cl.ID] = ctLog{operator: op.Name, url: cl.URL}
		}
		for _, tl := range op.TiledLogs {
			logs[tl.ID] = ctLog{operator: op.Name, url: tl.SubmissionURL}
		}
	}
	return logs
}

// readKnownLogs returns the knownLogs map from a file written by
// writeKnownLogs. A file that doesn't exist has no logs.
func readKnownLogs(path string) (map[string]ctLog, error) {
	logs := make(map[string]ctLog)
	src, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return logs, nil
	}
	if err != nil {
		return nil, err
	}

	file, err := parser.ParseFile(token.NewFileSet(), path, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	entries, err := knownLogsLiteral(file)
	if err != nil {
		return nil, err
	}

	for _, elt := range entries.Elts {
		entry, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return nil, fmt.Errorf("unexpected knownLogs element %T", elt)
		}
		id, err := stringLit(entry.Key)
		if err != nil {
			return nil, err
		}
		value, ok := entry.Value.(*ast.CompositeLit)
		if !ok {
			return nil, fmt.Errorf("unexpected value %T for log %s", entry.Value, id)
		}
		var l ctLog
		for _, elt := range value.Elts {
			field, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				return nil, fmt.Errorf("unexpected field %T for log %s", elt, id)
			}
			name, ok := field.Key.(*ast.Ident)
			if !ok {
				return nil, fmt.Errorf("unexpected field name %T for log %s", field.Key, id)
			}
			s, err := stringLit(field.Value)
			if err != nil {
				return nil, err
			}
			switch name.Name {
			case "operator":
				l.operator = s
			case "url":
				l.url = s
			default:
				return nil, fmt.Errorf("unknown field %s for log %s", name.Name, id)
			}
		}
		logs[id] = l
	}
	return logs, nil
}

// knownLogsLiteral returns the map literal assigned to knownLogs.
func knownLogsLiteral(file *ast.File) (*ast.CompositeLit, error) {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if name.Name != "knownLogs" || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.CompositeLit)
				if !ok {
					return nil, errors.New("knownLogs is not a map literal")
				}
				return lit, nil
			}
		}
	}
	return nil, errors.New("no knownLogs variable")
}

func stringLit(e ast.Expr) (string, error) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", fmt.Errorf("expected a string literal, found %T", e)
	}
	return strconv.Unquote(lit.Value)
}

func writeKnownLogs(w io.Writer, pkg string, list *logList, logs map[string]ctLog) error {
	// Sort by operator and URL, so that regenerating only changes the lines
	// for logs that changed.
	ids := slices.Collect(maps.Keys(logs))
	slices.SortFunc(ids, func(a, b string) int {
		return cmp.Or(
			cmp.Compare(logs[a].operator, logs[b].operator),
			cmp.Compare(logs[a].url, logs[b].url),
			cmp.Compare(a, b),
		)
	})

	if _, err := fmt.Fprintf(w, `// Code generated by github.com/square/certigo/internal/gen-known-logs; DO NOT EDIT.
// Logs from CT log list version %s (%s), plus logs from earlier
// versions that are no longer listed.
package %s

type ctLog struct {
	operator string
	url      string
}

var knownLogs = map[string]*ctLog{
`, list.Version, list.Timestamp, pkg); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := fmt.Fprintf(w, "\t%q: {operator: %q, url: %q},\n", id, logs[id].operator, logs[id].url); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w, "}")
	return err
}
