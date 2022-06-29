package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
)

var packageName = flag.String("package", "lib", "Package for the generated code")

// https://github.com/google/certificate-transparency-community-site/blob/master/docs/google/known-logs.md
const knownLogsAddr = "https://www.gstatic.com/ct/log_list/v2/all_logs_list.json"

type ctLog struct {
	operator string
	url      string
}

func main() {
	flag.Parse()

	resp, err := http.Get(knownLogsAddr)
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

	fmt.Printf(`// Autogenerated with github.com/square/certigo/internal/gen-known-logs
package %s

type ctLog struct {
	operator string
	url      string
}

var knownLogs = map[string]*ctLog{
`, *packageName)
	knownLogs := make(map[string]*ctLog)
	for _, op := range logs.Operators {
		for _, l := range op.Logs {
			fmt.Printf("\t%q: {operator: %q, url: %q},\n", l.ID, op.Name, l.URL)
			knownLogs[l.ID] = &ctLog{
				operator: op.Name,
				url:      l.URL,
			}
		}
	}
	fmt.Println("}")
}