# Find all non-vendor source files
SOURCE_FILES = $(shell find . \( -name '*.go' -not -path './vendor*' \)) 

depends:
	glide -q install

build:
	go build .

test:
	go test -v `glide novendor`

check:
	go vet -v `glide novendor`
	!(gofmt -d $(SOURCE_FILES) | grep .)
