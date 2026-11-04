package proxy

import (
	"fmt"
	"net"
	"sync"
)

type PortAllocator struct {
	mu       sync.Mutex
	minPort  int
	maxPort  int
	reserved map[int]string // port -> tenant_id/purpose
}

func NewPortAllocator(minPort, maxPort int) *PortAllocator {
	if minPort <= 0 {
		minPort = 10000
	}
	if maxPort <= minPort {
		maxPort = 60000
	}
	return &PortAllocator{
		minPort:  minPort,
		maxPort:  maxPort,
		reserved: make(map[int]string),
	}
}

// IsPortAvailable checks if a port is not in our reserved map and can be bound on 127.0.0.1
func (pa *PortAllocator) IsPortAvailable(port int) bool {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	if _, exists := pa.reserved[port]; exists {
		return false
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// AllocateNextPort finds and reserves the next available unprivileged loopback port
func (pa *PortAllocator) AllocateNextPort(purpose string) (int, error) {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	for port := pa.minPort; port <= pa.maxPort; port++ {
		if _, exists := pa.reserved[port]; exists {
			continue
		}

		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue // port in use by other process
		}
		_ = ln.Close()

		pa.reserved[port] = purpose
		return port, nil
	}

	return 0, fmt.Errorf("no available ports in range %d-%d", pa.minPort, pa.maxPort)
}

// ReleasePort frees an allocated port
func (pa *PortAllocator) ReleasePort(port int) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	delete(pa.reserved, port)
}
