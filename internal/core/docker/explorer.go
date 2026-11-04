package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"bee-panel/internal/storage"
)

type ContainerPort struct {
	IP          string `json:"ip,omitempty"`
	PrivatePort int    `json:"private_port"`
	PublicPort  int    `json:"public_port,omitempty"`
	Type        string `json:"type"`
}

type ContainerInfo struct {
	ID         string          `json:"id"`
	ShortID    string          `json:"short_id"`
	Names      []string        `json:"names"`
	DisplayName string         `json:"display_name"`
	Image      string          `json:"image"`
	State      string          `json:"state"`
	Status     string          `json:"status"`
	Ports      []ContainerPort `json:"ports"`
	Tenant     string          `json:"tenant"`
	Socket     string          `json:"socket"`
	Created    int64           `json:"created"`
}

type DockerExplorer struct{}

func NewDockerExplorer() *DockerExplorer {
	return &DockerExplorer{}
}

func getSocketHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 5 * time.Second,
	}
}

// ListAllContainers iterates across all tenant sockets and host docker socket to aggregate container list
func (e *DockerExplorer) ListAllContainers(tenants []*storage.Tenant) ([]ContainerInfo, error) {
	var result []ContainerInfo

	// 1. Check host root docker socket if available
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		hostContainers, _ := e.listContainersForSocket("/var/run/docker.sock", "system-root")
		result = append(result, hostContainers...)
	}

	// 2. Check each tenant's rootless socket
	for _, t := range tenants {
		socketPath := t.DockerSocket
		if socketPath == "" {
			socketPath = fmt.Sprintf("/run/user/%d/docker.sock", t.UID)
		}
		if _, err := os.Stat(socketPath); err == nil {
			tenantContainers, _ := e.listContainersForSocket(socketPath, t.Username)
			result = append(result, tenantContainers...)
		}
	}

	return result, nil
}

type rawDockerPort struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}

type rawDockerContainer struct {
	ID      string          `json:"Id"`
	Names   []string        `json:"Names"`
	Image   string          `json:"Image"`
	State   string          `json:"State"`
	Status  string          `json:"Status"`
	Created int64           `json:"Created"`
	Ports   []rawDockerPort `json:"Ports"`
}

func (e *DockerExplorer) listContainersForSocket(socketPath, tenant string) ([]ContainerInfo, error) {
	client := getSocketHTTPClient(socketPath)
	resp, err := client.Get("http://localhost/containers/json?all=1")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker api error (%d)", resp.StatusCode)
	}

	var rawList []rawDockerContainer
	if err := json.NewDecoder(resp.Body).Decode(&rawList); err != nil {
		return nil, err
	}

	var list []ContainerInfo
	for _, c := range rawList {
		shortID := c.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		displayName := shortID
		if len(c.Names) > 0 {
			displayName = strings.TrimPrefix(c.Names[0], "/")
		}

		var ports []ContainerPort
		for _, p := range c.Ports {
			ports = append(ports, ContainerPort{
				IP:          p.IP,
				PrivatePort: p.PrivatePort,
				PublicPort:  p.PublicPort,
				Type:        p.Type,
			})
		}

		list = append(list, ContainerInfo{
			ID:          c.ID,
			ShortID:     shortID,
			Names:       c.Names,
			DisplayName: displayName,
			Image:       c.Image,
			State:       c.State,
			Status:      c.Status,
			Ports:       ports,
			Tenant:      tenant,
			Socket:      socketPath,
			Created:     c.Created,
		})
	}

	return list, nil
}

// StartContainer sends start request to docker daemon
func (e *DockerExplorer) StartContainer(socketPath, containerID string) error {
	client := getSocketHTTPClient(socketPath)
	resp, err := client.Post(fmt.Sprintf("http://localhost/containers/%s/start", containerID), "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("start failed (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// StopContainer sends stop request to docker daemon
func (e *DockerExplorer) StopContainer(socketPath, containerID string) error {
	client := getSocketHTTPClient(socketPath)
	resp, err := client.Post(fmt.Sprintf("http://localhost/containers/%s/stop", containerID), "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("stop failed (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// RestartContainer sends restart request to docker daemon
func (e *DockerExplorer) RestartContainer(socketPath, containerID string) error {
	client := getSocketHTTPClient(socketPath)
	resp, err := client.Post(fmt.Sprintf("http://localhost/containers/%s/restart", containerID), "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("restart failed (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// GetContainerLogs fetches the last N lines from container stdout & stderr
func (e *DockerExplorer) GetContainerLogs(socketPath, containerID string, tailLines int) (string, error) {
	if tailLines <= 0 {
		tailLines = 100
	}
	client := getSocketHTTPClient(socketPath)
	url := fmt.Sprintf("http://localhost/containers/%s/logs?stdout=1&stderr=1&tail=%d", containerID, tailLines)
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	rawLogs, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Docker logs multiplexing header strip (each frame has 8-byte header)
	cleaned := cleanDockerLogs(rawLogs)
	return cleaned, nil
}

func cleanDockerLogs(raw []byte) string {
	var builder strings.Builder
	idx := 0
	for idx < len(raw) {
		if idx+8 > len(raw) {
			builder.Write(raw[idx:])
			break
		}
		// 8-byte header: [STREAM_TYPE, 0, 0, 0, SIZE1, SIZE2, SIZE3, SIZE4]
		size := int(raw[idx+4])<<24 | int(raw[idx+5])<<16 | int(raw[idx+6])<<8 | int(raw[idx+7])
		idx += 8
		if size <= 0 || idx+size > len(raw) {
			builder.Write(raw[idx:])
			break
		}
		builder.Write(raw[idx : idx+size])
		idx += size
	}
	return builder.String()
}
