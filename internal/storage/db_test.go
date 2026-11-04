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

func TestIsPortInUse(t *testing.T) {
	tempDB := filepath.Join(t.TempDir(), "test.db")
	db, err := OpenDB(tempDB)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer db.Close()

	// Initial: port 3000 should not be in use
	inUse, err := db.IsPortInUse(3000, "")
	if err != nil || inUse {
		t.Fatalf("expected 3000 not in use, got inUse=%v, err=%v", inUse, err)
	}

	tenant, err := db.CreateTenant("testtenant", 1001, 1001, "/home/testtenant", "")
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Add a domain mapping with target port 3000
	m := &DomainMapping{
		TenantID:            tenant.ID,
		Domain:              "app1.example.com",
		ExternalPort:        80,
		TargetContainerPort: 3000,
	}
	if err := db.SaveDomainMapping(m); err != nil {
		t.Fatalf("SaveDomainMapping failed: %v", err)
	}

	// Port 3000 should now be in use
	inUse, err = db.IsPortInUse(3000, "")
	if err != nil || !inUse {
		t.Fatalf("expected 3000 in use, got inUse=%v, err=%v", inUse, err)
	}

	// Port 3000 should NOT be in use if excluded domain is app1.example.com
	inUse, err = db.IsPortInUse(3000, "app1.example.com")
	if err != nil || inUse {
		t.Fatalf("expected 3000 not in use when excluding app1, got inUse=%v, err=%v", inUse, err)
	}

	// Add second domain with same port 3000
	m2 := &DomainMapping{
		TenantID:            tenant.ID,
		Domain:              "app2.example.com",
		ExternalPort:        80,
		TargetContainerPort: 3000,
	}
	if err := db.SaveDomainMapping(m2); err != nil {
		t.Fatalf("SaveDomainMapping failed: %v", err)
	}

	// Now excluding app1 should STILL report in use because app2 is using it
	inUse, err = db.IsPortInUse(3000, "app1.example.com")
	if err != nil || !inUse {
		t.Fatalf("expected 3000 still in use by app2, got inUse=%v, err=%v", inUse, err)
	}
}
