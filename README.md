# Google Discovery

Dependency-light Go parsing for Google Discovery documents.

`github.com/OpenUdon/googlediscovery` parses official Google Discovery JSON into
native metadata for downstream protocol-aware tools. It preserves service
metadata, schemas, OAuth scopes, inherited parameters, flattened operations, and
media upload hints without treating Discovery as OpenAPI.

## Install

```bash
go get github.com/OpenUdon/googlediscovery
```

## Example

```go
package main

import (
	"fmt"
	"os"

	"github.com/OpenUdon/googlediscovery"
)

func main() {
	data, err := os.ReadFile("drive.discovery.json")
	if err != nil {
		panic(err)
	}

	model, err := googlediscovery.Parse(data)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s %s has %d operations\n", model.Name, model.Version, len(model.Operations))
}
```

## Scope

This package is metadata-only. It does not execute Google APIs, resolve
credentials, fetch tokens, choose Google projects/accounts, or convert Discovery
documents to OpenAPI.

Google publishes a protobuf model for Discovery in
`github.com/google/gnostic-models/discovery`. This package keeps a smaller
runtime dependency surface and uses Google Discovery/`discovery.proto` as a
reference for parser fidelity. The optional `tools/gnostic-compare` module keeps
that upstream dependency isolated from the root module.

## Verification

```bash
GOWORK=off go test ./...
GOWORK=off go vet ./...
git diff --check
(cd tools/gnostic-compare && GOWORK=off go test ./...)
```
