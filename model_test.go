package googlediscovery

import (
	"os"
	"path/filepath"
	"reflect"
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
