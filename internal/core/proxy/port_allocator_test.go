package proxy

import (
	"testing"
)

func TestPortAllocator(t *testing.T) {
	pa := NewPortAllocator(20000, 20005)

	p1, err := pa.AllocateNextPort("tenant-1")
	if err != nil {
		t.Fatalf("unexpected error allocating port: %v", err)
	}
	if p1 < 20000 || p1 > 20005 {
		t.Errorf("expected port in range 20000-20005, got %d", p1)
	}

	p2, err := pa.AllocateNextPort("tenant-2")
	if err != nil {
		t.Fatalf("unexpected error allocating second port: %v", err)
	}
	if p1 == p2 {
		t.Errorf("allocated ports should be unique: p1=%d, p2=%d", p1, p2)
	}

	pa.ReleasePort(p1)
	if !pa.IsPortAvailable(p1) {
		t.Errorf("port %d should be available after release", p1)
	}
}
