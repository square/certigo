# gen-known-logs

A tool for generating the list of CT logs that certigo uses for printing operator information and log URLs for SCTs.

Logs are fetched parsed from https://www.gstatic.com/ct/log_list/v2/all_logs_list.json, documented [here](https://github.com/google/certificate-transparency-community-site/blob/master/docs/google/known-logs.md).

## Usage

Run `go generate ./...` to regenerate known logs.