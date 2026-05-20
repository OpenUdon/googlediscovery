package gnosticcompare

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenUdon/googlediscovery"
	gnosticdiscovery "github.com/google/gnostic-models/discovery"
)

func TestCatalogFixturesAgainstGnosticModels(t *testing.T) {
	tests := []struct {
		file       string
		name       string
		version    string
		gnosticErr string
	}{
		{
			file:       "calendar.v3.discovery.json",
			name:       "calendar",
			version:    "v3",
			gnosticErr: "",
		},
		{
			file:       "drive.v3.discovery.json",
			name:       "drive",
			version:    "v3",
			gnosticErr: "invalid property: deprecated",
		},
		{
			file:       "gmail.v1.discovery.json",
			name:       "gmail",
			version:    "v1",
			gnosticErr: "invalid property: deprecated",
		},
		{
			file:       "sheets.v4.discovery.json",
			name:       "sheets",
			version:    "v4",
			gnosticErr: "invalid property: deprecated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_"+tt.version, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "catalog", tt.file))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}

			model, err := googlediscovery.Parse(data)
			if err != nil {
				t.Fatalf("googlediscovery.Parse failed: %v", err)
			}
			if got := model.Name; got != tt.name {
				t.Fatalf("googlediscovery name = %q, want %q", got, tt.name)
			}
			if got := model.Version; got != tt.version {
				t.Fatalf("googlediscovery version = %q, want %q", got, tt.version)
			}

			_, err = gnosticdiscovery.ParseDocument(data)
			if tt.gnosticErr == "" {
				if err != nil {
					t.Fatalf("gnostic-models ParseDocument failed: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("gnostic-models ParseDocument succeeded, want error containing %q", tt.gnosticErr)
			}
			if !strings.Contains(err.Error(), tt.gnosticErr) {
				t.Fatalf("gnostic-models error = %q, want substring %q", err.Error(), tt.gnosticErr)
			}
		})
	}
}
