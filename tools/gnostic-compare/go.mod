module github.com/OpenUdon/googlediscovery/tools/gnostic-compare

go 1.25.5

require (
	github.com/OpenUdon/googlediscovery v0.0.0
	github.com/google/gnostic-models v0.7.1
)

require (
	go.yaml.in/yaml/v3 v3.0.3 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
)

replace github.com/OpenUdon/googlediscovery => ../..
