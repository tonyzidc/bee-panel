package storage

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestEmptyListsReturnNonNilSlices(t *testing.T) {
	tempDB := filepath.Join(t.TempDir(), "test.db")
	db, err := OpenDB(tempDB)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer db.Close()

	// 1. Tenants
	tenants, err := db.ListTenants()
	if err != nil {
		t.Fatalf("ListTenants error: %v", err)
	}
	data, _ := json.Marshal(tenants)
	if string(data) != "[]" {
		t.Errorf("expected ListTenants JSON '[]', got %q", string(data))
	}

	// 2. Domain mappings
	domains, err := db.ListDomainMappings(0)
	if err != nil {
		t.Fatalf("ListDomainMappings error: %v", err)
	}
	data, _ = json.Marshal(domains)
	if string(data) != "[]" {
		t.Errorf("expected ListDomainMappings JSON '[]', got %q", string(data))
	}

	// 3. Domain mappings with tenant
	domainsWithTenant, err := db.ListDomainMappingsWithTenant()
	if err != nil {
		t.Fatalf("ListDomainMappingsWithTenant error: %v", err)
	}
	data, _ = json.Marshal(domainsWithTenant)
	if string(data) != "[]" {
		t.Errorf("expected ListDomainMappingsWithTenant JSON '[]', got %q", string(data))
	}
}
