package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

type SOFAData struct {
	OSVersions []OSVersion `json:"OSVersions"`
	Models     map[string]Model `json:"Models"`
}

type OSVersion struct {
	OSVersion string `json:"OSVersion"`
}

type Model struct {
	SupportedOS []string `json:"SupportedOS"`
}

// MacOSCompatibilityTable implements the table plugin
type MacOSCompatibilityTable struct {
	cacheDir    string
	jsonCache   string
	etagCache   string
	sofaURL     string
	userAgent   string
	httpClient  *http.Client
}

// NewMacOSCompatibilityTable creates a new instance of the table
func NewMacOSCompatibilityTable() *MacOSCompatibilityTable {
	return &MacOSCompatibilityTable{
		cacheDir:   "/private/var/tmp/sofa",
		sofaURL:    "https://sofafeed.macadmins.io/v1/macos_data_feed.json",
		userAgent:  "SOFA-osquery-macOSCompatibilityCheck/1.0",
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// MacOSCompatibilityColumns returns the columns that our table will return
func MacOSCompatibilityColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("system_version"),
		table.TextColumn("system_os_major"),
		table.TextColumn("model_identifier"),
		table.TextColumn("latest_macos"),
		table.TextColumn("latest_compatible_macos"),
		table.IntegerColumn("is_compatible"),
		table.TextColumn("status"),
	}
}

// MacOSCompatibilityGenerate will be called whenever the table is queried
func MacOSCompatibilityGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	table := NewMacOSCompatibilityTable()
	
	// Set up cache file paths
	table.jsonCache = filepath.Join(table.cacheDir, "macos_data_feed.json")
	table.etagCache = filepath.Join(table.cacheDir, "macos_data_feed_etag.txt")

	// Get system information
	systemVersion, systemOSMajor, modelIdentifier, err := table.getSystemInfo(ctx)
	if err != nil {
		return []map[string]string{{
			"system_version":           "Unknown",
			"system_os_major":          "Unknown",
			"model_identifier":         "Unknown",
			"latest_macos":             "Unknown",
			"latest_compatible_macos":  "Unknown",
			"is_compatible":            "-1",
			"status":                   fmt.Sprintf("Error getting system info: %v", err),
		}}, nil
	}

	// Fetch SOFA data
	sofaData, err := table.fetchSofaData()
	if err != nil {
		return []map[string]string{{
			"system_version":           systemVersion,
			"system_os_major":          systemOSMajor,
			"model_identifier":         modelIdentifier,
			"latest_macos":             "Unknown",
			"latest_compatible_macos":  "Unknown",
			"is_compatible":            "-1",
			"status":                   fmt.Sprintf("Could not obtain data: %v", err),
		}}, nil
	}

	// Process the data
	result := table.processSofaData(sofaData, systemVersion, systemOSMajor, modelIdentifier)
	return []map[string]string{result}, nil
}

// getSystemInfo retrieves system information
func (m *MacOSCompatibilityTable) getSystemInfo(ctx context.Context) (string, string, string, error) {
	// Get system version
	systemVersion, err := m.getSystemVersion()
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get system version: %v", err)
	}

	// Extract major OS version (e.g., 14 from 14.5)
	systemOSMajor := strings.Split(systemVersion, ".")[0]

	// Get model identifier
	modelIdentifier, err := m.getModelIdentifier()
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get model identifier: %v", err)
	}

	return systemVersion, systemOSMajor, modelIdentifier, nil
}

// getSystemVersion gets the macOS version
func (m *MacOSCompatibilityTable) getSystemVersion() (string, error) {
	cmd := exec.Command("sw_vers", "-productVersion")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// getModelIdentifier gets the hardware model identifier
func (m *MacOSCompatibilityTable) getModelIdentifier() (string, error) {
	cmd := exec.Command("sysctl", "-n", "hw.model")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// ensureCacheDir creates the cache directory if it doesn't exist
func (m *MacOSCompatibilityTable) ensureCacheDir() error {
	if _, err := os.Stat(m.cacheDir); os.IsNotExist(err) {
		return os.MkdirAll(m.cacheDir, 0755)
	}
	return nil
}

// readFile reads content from a file
func (m *MacOSCompatibilityTable) readFile(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// writeFile writes content to a file
func (m *MacOSCompatibilityTable) writeFile(filename string, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

// fetchSofaData fetches SOFA data with ETag caching
func (m *MacOSCompatibilityTable) fetchSofaData() (*SOFAData, error) {
	if err := m.ensureCacheDir(); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %v", err)
	}

	// Read cached ETag if available
	var etag string
	if cachedEtag, err := m.readFile(m.etagCache); err == nil {
		etag = strings.TrimSpace(cachedEtag)
	}

	// Create request
	req, err := http.NewRequest("GET", m.sofaURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("User-Agent", m.userAgent)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	// Make request
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Handle 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		// Use cached data
		cachedData, err := m.readFile(m.jsonCache)
		if err != nil {
			return nil, fmt.Errorf("failed to read cached data: %v", err)
		}
		
		var sofaData SOFAData
		if err := json.Unmarshal([]byte(cachedData), &sofaData); err != nil {
			return nil, fmt.Errorf("failed to parse cached data: %v", err)
		}
		return &sofaData, nil
	}

	// Handle successful response
	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}

		// Cache the new data
		if err := m.writeFile(m.jsonCache, string(body)); err != nil {
			// Log but don't fail
			log.Printf("Warning: failed to cache data: %v", err)
		}

		// Cache the new ETag if available
		if newEtag := resp.Header.Get("ETag"); newEtag != "" {
			if err := m.writeFile(m.etagCache, newEtag); err != nil {
				// Log but don't fail
				log.Printf("Warning: failed to cache ETag: %v", err)
			}
		}

		var sofaData SOFAData
		if err := json.Unmarshal(body, &sofaData); err != nil {
			return nil, fmt.Errorf("failed to parse SOFA data: %v", err)
		}
		return &sofaData, nil
	}

	// Try to use cached data if available
	if cachedData, err := m.readFile(m.jsonCache); err == nil && cachedData != "" {
		log.Printf("Warning: failed to fetch new data (HTTP %d), using cached data", resp.StatusCode)
		var sofaData SOFAData
		if err := json.Unmarshal([]byte(cachedData), &sofaData); err != nil {
			return nil, fmt.Errorf("failed to parse cached data: %v", err)
		}
		return &sofaData, nil
	}

	return nil, fmt.Errorf("failed to fetch SOFA data (HTTP %d) and no cache available", resp.StatusCode)
}

// processSofaData processes the SOFA data and returns a result row
func (m *MacOSCompatibilityTable) processSofaData(sofaData *SOFAData, systemVersion, systemOSMajor, modelIdentifier string) map[string]string {
	result := map[string]string{
		"system_version":  systemVersion,
		"system_os_major": systemOSMajor,
		"model_identifier": modelIdentifier,
	}

	if len(sofaData.OSVersions) == 0 {
		result["latest_macos"] = "Unknown"
		result["latest_compatible_macos"] = "Unknown"
		result["is_compatible"] = "-1"
		result["status"] = "No OS versions in SOFA data"
		return result
	}

	latestOS := sofaData.OSVersions[0].OSVersion
	result["latest_macos"] = latestOS

	// Check if model is virtual
	if strings.Contains(modelIdentifier, "VirtualMac") {
		modelIdentifier = "Macmini9,1" // Use M1 Mac mini as reference for VMs
		result["model_identifier"] = modelIdentifier
	}

	// Check if model exists in the feed
	model, exists := sofaData.Models[modelIdentifier]
	latestCompatibleOS := "Unsupported"
	status := "Pass"

	if exists && len(model.SupportedOS) > 0 {
		latestCompatibleOS = model.SupportedOS[0]
	} else {
		status = "Unsupported Hardware"
	}

	result["latest_compatible_macos"] = latestCompatibleOS

	// Determine compatibility
	isCompatible := (latestOS == latestCompatibleOS)
	if !isCompatible && status != "Unsupported Hardware" {
		status = "Fail"
	}

	if isCompatible {
		result["is_compatible"] = "1"
	} else {
		result["is_compatible"] = "0"
	}
	result["status"] = status

	return result
}

func main() {
	var socket string
	
	// Manually parse arguments to ignore unknown flags
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "-socket" || arg == "--socket" {
			if i+1 < len(os.Args) {
				socket = os.Args[i+1]
				i++ // skip the value
			}
		} else if strings.HasPrefix(arg, "-socket=") || strings.HasPrefix(arg, "--socket=") {
			socket = strings.TrimPrefix(strings.TrimPrefix(arg, "-socket="), "--socket=")
		}
		// Ignore all other flags including -timeout
	}
	
	// If no socket is provided, try to get it from environment variable
	if socket == "" {
		socket = os.Getenv("OSQUERY_EXTENSION_SOCKET")
	}
	
	if socket == "" {
		log.Fatalf(`Usage: %s --socket SOCKET_PATH`, os.Args[0])
	}

	server, err := osquery.NewExtensionManagerServer("macos_compatibility", socket)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// Create and register a new table plugin with the server.
	// table.NewPlugin requires the table plugin name,
	// a slice of Columns and a Generate function.
	server.RegisterPlugin(table.NewPlugin("macos_compatibility", MacOSCompatibilityColumns(), MacOSCompatibilityGenerate))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
} 