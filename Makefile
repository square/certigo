# Find all non-vendor source files
SOURCE_FILES = $(shell find . \( -name '*.go' -not -path './vendor*' \)) 

depends:
	glide -q install

build:
	go build .

check:
	go vet -v .
	!(gofmt -d $(SOURCE_FILES) | grep .)
