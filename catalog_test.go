package googlediscovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCatalogDiscoveryFixtures(t *testing.T) {
	tests := []struct {
		file       string
		name       string
		version    string
		title      string
		schemas    int
		operations int
		scopes     int
		wantOps    []string
	}{
		{
			file:       "calendar.v3.discovery.json",
			name:       "calendar",
			version:    "v3",
			title:      "Calendar API",
			schemas:    39,
			operations: 37,
			scopes:     17,
			wantOps:    []string{"calendar_events_list"},
		},
		{
			file:       "drive.v3.discovery.json",
			name:       "drive",
			version:    "v3",
			title:      "Google Drive API",
			schemas:    54,
			operations: 64,
			scopes:     10,
			wantOps:    []string{"drive_files_create"},
		},
		{
			file:       "gmail.v1.discovery.json",
			name:       "gmail",
			version:    "v1",
			title:      "Gmail API",
			schemas:    56,
			operations: 79,
			scopes:     14,
			wantOps:    []string{"gmail_users_messages_send"},
		},
		{
			file:       "sheets.v4.discovery.json",
			name:       "sheets",
			version:    "v4",
			title:      "Google Sheets API",
			schemas:    262,
			operations: 17,
			scopes:     5,
			wantOps:    []string{"sheets_spreadsheets_values_batchupdate"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_"+tt.version, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "catalog", tt.file))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			model, err := Parse(data)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			if got := model.Name; got != tt.name {
				t.Fatalf("name = %q, want %q", got, tt.name)
			}
			if got := model.Version; got != tt.version {
				t.Fatalf("version = %q, want %q", got, tt.version)
			}
			if got := model.Title; got != tt.title {
				t.Fatalf("title = %q, want %q", got, tt.title)
			}
			if got := len(model.Schemas); got != tt.schemas {
				t.Fatalf("schemas = %d, want %d", got, tt.schemas)
			}
			if got := len(model.Operations); got != tt.operations {
				t.Fatalf("operations = %d, want %d", got, tt.operations)
			}
			if got := len(model.OAuth2Scopes); got != tt.scopes {
				t.Fatalf("oauth scopes = %d, want %d", got, tt.scopes)
			}
			for _, name := range tt.wantOps {
				if _, ok := model.OperationByName(name); !ok {
					t.Fatalf("missing representative operation %q", name)
				}
			}
		})
	}
}
