Original C++ code converted with the help of AI - I am not a Go dev.

## Table Schema

| Column | Type | Description |
|--------|------|-------------|
| `system_version` | TEXT | Current macOS version  |
| `system_os_major` | TEXT | Major OS version  |
| `model_identifier` | TEXT | Hardware model identifier  |
| `latest_macos` | TEXT | Latest available macOS version |
| `latest_compatible_macos` | TEXT | Latest compatible macOS version for model |
| `is_compatible` | INTEGER | 1 if compatible, 0 if not, -1 for errors |
| `status` | TEXT | "Pass", "Fail", "Unsupported Hardware", or error |


## Building the Extension

1. Clone the repository

2. Install dependencies:
   ```bash
   go mod tidy
   ```

3. Build the extension:
   ```bash
   go build -o macos_compatibility.ext
   ```

To run locally with Fleet, `sudo orbit shell -- --extension macos_compatibility.ext --allow-unsafe`

or with standard osqueryi: `osqueryi --extension=/path/to/macos_compatibility.ext`

## Structure

```
macos-compatibility-table-go/
├── main.go              # Main extension code
├── go.mod               # Go module definition
├── go.sum               # Dependency 
└── README.md            # You are here
```
