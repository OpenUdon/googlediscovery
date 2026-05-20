package googlediscovery

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseDriveDiscoveryModel(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "drive.discovery.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	model, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if got, want := model.Title, "Google Drive API"; got != want {
		t.Fatalf("title = %q, want %q", got, want)
	}
	if got, want := model.ServerURL, "https://www.googleapis.com"; got != want {
		t.Fatalf("server url = %q, want %q", got, want)
	}
	if _, ok := model.Schema("File"); !ok {
		t.Fatal("missing File schema")
	}
	create, ok := model.OperationByName("drive_files_create")
	if !ok {
		t.Fatal("missing drive_files_create")
	}
	if got, want := create.Path, "/upload/drive/v3/files"; got != want {
		t.Fatalf("create path = %q, want %q", got, want)
	}
	if got, want := create.RequestMediaType, "multipart/related"; got != want {
		t.Fatalf("request media type = %q, want %q", got, want)
	}
	if create.MediaUpload == nil || !create.MediaUpload.Multipart {
		t.Fatalf("media upload = %#v, want multipart upload", create.MediaUpload)
	}
}

func TestParsePreservesOAuthScopesAndInheritedParameters(t *testing.T) {
	model, err := ParseMap(map[string]any{
		"auth": map[string]any{
			"oauth2": map[string]any{
				"scopes": map[string]any{
					"https://www.googleapis.com/auth/example.read": map[string]any{
						"description": "Read example resources",
					},
				},
			},
		},
		"parameters": map[string]any{
			"fields": map[string]any{"type": "string", "location": "query"},
		},
		"methods": map[string]any{
			"list": map[string]any{
				"id":         "examples.list",
				"httpMethod": "GET",
				"path":       "examples/{id}",
				"parameters": map[string]any{
					"id": map[string]any{"type": "string", "location": "path", "required": true},
				},
				"scopes": []any{"https://www.googleapis.com/auth/example.read"},
			},
		},
	})
	if err != nil {
		t.Fatalf("ParseMap failed: %v", err)
	}
	if got, want := model.OAuth2Scopes["https://www.googleapis.com/auth/example.read"], "Read example resources"; got != want {
		t.Fatalf("scope description = %q, want %q", got, want)
	}
	op, ok := model.OperationByName("examples_list")
	if !ok {
		t.Fatal("missing operation")
	}
	if got, want := op.Scopes, []string{"https://www.googleapis.com/auth/example.read"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scopes = %#v, want %#v", got, want)
	}
	var names []string
	for _, param := range op.Parameters {
		names = append(names, param.Location+":"+param.Name)
	}
	if got, want := names, []string{"query:fields", "path:id"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("parameters = %#v, want %#v", got, want)
	}
}

func TestParseAllowsSamePathDiscoveryOperations(t *testing.T) {
	model, err := ParseMap(map[string]any{
		"methods": map[string]any{
			"alpha": map[string]any{
				"id":         "things.alpha",
				"httpMethod": "GET",
				"path":       "things/{id}",
			},
			"beta": map[string]any{
				"id":         "things.beta",
				"httpMethod": "GET",
				"path":       "things/{id}",
			},
		},
	})
	if err != nil {
		t.Fatalf("ParseMap failed: %v", err)
	}
	if got, want := len(model.Operations), 2; got != want {
		t.Fatalf("operations = %d, want %d", got, want)
	}
}

func TestParsePreservesAllMediaUploadProtocols(t *testing.T) {
	model, err := ParseMap(map[string]any{
		"methods": map[string]any{
			"upload": map[string]any{
				"id":         "things.upload",
				"httpMethod": "POST",
				"path":       "things",
				"mediaUpload": map[string]any{
					"protocols": map[string]any{
						"resumable": map[string]any{
							"multipart": true,
							"path":      "/resumable/things",
						},
						"simple": map[string]any{
							"multipart": false,
							"path":      "/upload/things",
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("ParseMap failed: %v", err)
	}
	op, ok := model.OperationByName("things_upload")
	if !ok {
		t.Fatal("missing operation")
	}
	if got, want := op.MediaUpload.Protocol, "simple"; got != want {
		t.Fatalf("selected upload protocol = %q, want %q", got, want)
	}
	if got, want := op.MediaUploads["resumable"].Path, "/resumable/things"; got != want {
		t.Fatalf("resumable path = %q, want %q", got, want)
	}
}

func TestParsePreservesRefSiblingsAndDiscoveryEnumMetadata(t *testing.T) {
	model, err := ParseMap(map[string]any{
		"schemas": map[string]any{
			"Owner": map[string]any{"type": "object"},
			"Thing": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"owner": map[string]any{
						"$ref":        "Owner",
						"description": "Resource owner.",
						"deprecated":  true,
					},
					"state": map[string]any{
						"type":             "string",
						"enum":             []any{"ACTIVE"},
						"enumDescriptions": []any{"Active resource."},
					},
				},
			},
		},
		"methods": map[string]any{
			"list": map[string]any{
				"id":         "things.list",
				"httpMethod": "GET",
				"path":       "things",
				"parameters": map[string]any{
					"state": map[string]any{
						"type":             "string",
						"location":         "query",
						"enum":             []any{"ACTIVE"},
						"enumDescriptions": []any{"Active resource."},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("ParseMap failed: %v", err)
	}
	thing, ok := model.Schema("Thing")
	if !ok {
		t.Fatal("missing Thing schema")
	}
	props := thing["properties"].(map[string]any)
	owner := props["owner"].(map[string]any)
	if got, want := owner["$ref"], "#/components/schemas/Owner"; got != want {
		t.Fatalf("owner ref = %#v, want %#v", got, want)
	}
	if got, want := owner["description"], "Resource owner."; got != want {
		t.Fatalf("owner description = %#v, want %#v", got, want)
	}
	if got, want := owner["deprecated"], true; got != want {
		t.Fatalf("owner deprecated = %#v, want %#v", got, want)
	}
	state := props["state"].(map[string]any)
	if got, want := state["enumDescriptions"], []any{"Active resource."}; !reflect.DeepEqual(got, want) {
		t.Fatalf("schema enumDescriptions = %#v, want %#v", got, want)
	}
	op, ok := model.OperationByName("things_list")
	if !ok {
		t.Fatal("missing things_list")
	}
	if got, want := op.Parameters[0].Schema["enumDescriptions"], []any{"Active resource."}; !reflect.DeepEqual(got, want) {
		t.Fatalf("parameter enumDescriptions = %#v, want %#v", got, want)
	}
}

func TestParsePreservesDiscoveryDefaultsAndNormalizesConstraints(t *testing.T) {
	model, err := ParseMap(map[string]any{
		"schemas": map[string]any{
			"Thing": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"count": map[string]any{
						"type":    "integer",
						"default": "0",
						"minimum": "1",
					},
					"enabled": map[string]any{
						"type":    "boolean",
						"default": "false",
					},
				},
			},
		},
		"methods": map[string]any{
			"list": map[string]any{
				"id":         "things.list",
				"httpMethod": "GET",
				"path":       "things",
				"parameters": map[string]any{
					"maxResults": map[string]any{
						"type":     "integer",
						"location": "query",
						"default":  "100",
						"minimum":  "1",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("ParseMap failed: %v", err)
	}
	thing, ok := model.Schema("Thing")
	if !ok {
		t.Fatal("missing Thing schema")
	}
	props := thing["properties"].(map[string]any)
	count := props["count"].(map[string]any)
	if got, want := count["default"], "0"; got != want {
		t.Fatalf("schema default = %#v, want %#v", got, want)
	}
	if got, want := count["minimum"], float64(1); got != want {
		t.Fatalf("schema minimum = %#v, want %#v", got, want)
	}
	enabled := props["enabled"].(map[string]any)
	if got, want := enabled["default"], "false"; got != want {
		t.Fatalf("boolean default = %#v, want %#v", got, want)
	}
	op, ok := model.OperationByName("things_list")
	if !ok {
		t.Fatal("missing things_list")
	}
	if got, want := op.Parameters[0].Schema["default"], "100"; got != want {
		t.Fatalf("parameter default = %#v, want %#v", got, want)
	}
	if got, want := op.Parameters[0].Schema["minimum"], float64(1); got != want {
		t.Fatalf("parameter minimum = %#v, want %#v", got, want)
	}
}

func TestParseRejectsMalformedKnownNestedFields(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]any
		want string
	}{
		{
			name: "schema_items",
			raw: map[string]any{
				"schemas": map[string]any{
					"Thing": map[string]any{"type": "array", "items": "bad"},
				},
			},
			want: "schemas.Thing.items must be an object",
		},
		{
			name: "schema_composition",
			raw: map[string]any{
				"schemas": map[string]any{
					"Thing": map[string]any{"allOf": map[string]any{}},
				},
			},
			want: "schemas.Thing.allOf must be an array",
		},
		{
			name: "oauth_scope",
			raw: map[string]any{
				"auth": map[string]any{
					"oauth2": map[string]any{
						"scopes": map[string]any{
							"https://www.googleapis.com/auth/example": "bad",
						},
					},
				},
			},
			want: "must be an object",
		},
		{
			name: "media_upload_protocol",
			raw: map[string]any{
				"methods": map[string]any{
					"upload": map[string]any{
						"id":         "things.upload",
						"httpMethod": "POST",
						"path":       "things",
						"mediaUpload": map[string]any{
							"protocols": map[string]any{
								"simple": "bad",
							},
						},
					},
				},
			},
			want: "mediaUpload.protocols.simple must be an object",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseMap(tt.raw)
			if err == nil {
				t.Fatal("ParseMap succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.want)
			}
		})
	}
}

func TestParseRejectsExcessiveNesting(t *testing.T) {
	t.Run("resources", func(t *testing.T) {
		resources := map[string]any{}
		current := resources
		for i := 0; i <= maxDiscoveryNestingDepth+1; i++ {
			next := map[string]any{}
			current["r"] = map[string]any{"resources": next}
			current = next
		}
		_, err := ParseMap(map[string]any{"resources": resources})
		if err == nil {
			t.Fatal("ParseMap succeeded, want depth error")
		}
		if !strings.Contains(err.Error(), "resource nesting exceeds") {
			t.Fatalf("error = %q, want resource nesting error", err.Error())
		}
	})

	t.Run("schemas", func(t *testing.T) {
		schema := map[string]any{"type": "array"}
		current := schema
		for i := 0; i <= maxDiscoveryNestingDepth+1; i++ {
			next := map[string]any{"type": "array"}
			current["items"] = next
			current = next
		}
		_, err := ParseMap(map[string]any{"schemas": map[string]any{"Thing": schema}})
		if err == nil {
			t.Fatal("ParseMap succeeded, want depth error")
		}
		if !strings.Contains(err.Error(), "exceeds schema nesting limit") {
			t.Fatalf("error = %q, want schema nesting error", err.Error())
		}
	})
}
