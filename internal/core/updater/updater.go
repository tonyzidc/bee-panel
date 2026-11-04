package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	CurrentVersion = "v0.2.0"
	GitHubRepo     = "tonyzidc/bee-panel"
)

type GitHubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

type UpdateInfo struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	HasUpdate      bool   `json:"has_update"`
	ReleaseNotes   string `json:"release_notes"`
	PublishedAt    string `json:"published_at"`
	DownloadURL    string `json:"download_url"`
}

type Updater struct {
	client *http.Client
}

func NewUpdater() *Updater {
	return &Updater{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// CheckUpdate queries GitHub for the latest release
func (u *Updater) CheckUpdate() (*UpdateInfo, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", GitHubRepo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "Bee-Panel-Updater")

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("check update request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &UpdateInfo{
			CurrentVersion: CurrentVersion,
			LatestVersion:  CurrentVersion,
			HasUpdate:      false,
			ReleaseNotes:   "No newer releases found on GitHub repository.",
			PublishedAt:    time.Now().Format("2006-01-02 15:04:05"),
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned status %d", resp.StatusCode)
	}

	var rel GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode release json: %w", err)
	}

	targetAsset := fmt.Sprintf("bee-panel-%s-%s", runtime.GOOS, runtime.GOARCH)
	var downloadURL string
	for _, a := range rel.Assets {
		if strings.Contains(a.Name, targetAsset) {
			downloadURL = a.BrowserDownloadURL
			break
		}
	}

	hasUpdate := false
	if rel.TagName != "" && rel.TagName != CurrentVersion {
		hasUpdate = true
	}

	return &UpdateInfo{
		CurrentVersion: CurrentVersion,
		LatestVersion:  rel.TagName,
		HasUpdate:      hasUpdate,
		ReleaseNotes:   rel.Body,
		PublishedAt:    rel.PublishedAt.Format("2006-01-02 15:04:05"),
		DownloadURL:    downloadURL,
	}, nil
}

// PerformSelfUpdate downloads the new binary, replaces the current executable, and restarts daemon
func (u *Updater) PerformSelfUpdate() error {
	info, err := u.CheckUpdate()
	if err != nil {
		return err
	}

	if info.DownloadURL == "" {
		return fmt.Errorf("no matching binary found for %s-%s in release %s", runtime.GOOS, runtime.GOARCH, info.LatestVersion)
	}

	execPath, err := os.Executable()
	if err != nil {
		execPath = "/usr/local/bin/bee-panel"
	}

	tmpPath := execPath + ".update"
	bakPath := execPath + ".bak"

	// 1. Download new binary
	resp, err := http.Get(info.DownloadURL)
	if err != nil {
		return fmt.Errorf("download error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("create update file: %w", err)
	}
	_, err = io.Copy(out, resp.Body)
	_ = out.Close()
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("save update file: %w", err)
	}

	// 2. Validate binary test run
	testCmd := exec.Command(tmpPath, "version")
	if testOut, err := testCmd.CombinedOutput(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("downloaded binary validation failed: %s (%w)", string(testOut), err)
	}

	// 3. Backup and replace
	_ = os.Remove(bakPath)
	_ = os.Rename(execPath, bakPath)
	if err := os.Rename(tmpPath, execPath); err != nil {
		// Restore backup
		_ = os.Rename(bakPath, execPath)
		return fmt.Errorf("replace binary failed: %w", err)
	}

	// 4. Detached restart of bee-panel systemd service
	go func() {
		time.Sleep(1 * time.Second)
		_ = exec.Command("systemctl", "restart", "bee-panel").Run()
	}()

	return nil
}
