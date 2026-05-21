package tools

type InventoryScanResult struct {
	SchemaVersion string               `json:"schema_version"`
	Host          string               `json:"host"`
	ScannedAt     string               `json:"scanned_at"`
	Collectors    []InventoryCollector `json:"collectors"`
	Identity      HostIdentity         `json:"identity"`
	Packages      []InventoryPackage   `json:"packages"`
	Services      []InventoryService   `json:"services"`
	Processes     []InventoryProcess   `json:"processes"`
	Ports         []InventoryPort      `json:"ports"`
	Containers    []InventoryContainer `json:"containers"`
	Wazuh         WazuhHint            `json:"wazuh"`
}

type InventoryCollector struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}

type HostIdentity struct {
	Hostname     string            `json:"hostname,omitempty"`
	Kernel       string            `json:"kernel,omitempty"`
	Architecture string            `json:"architecture,omitempty"`
	Uptime       string            `json:"uptime,omitempty"`
	OSRelease    map[string]string `json:"os_release,omitempty"`
}

type InventoryPackage struct {
	Manager string `json:"manager"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
}

type InventoryService struct {
	Name        string `json:"name"`
	LoadState   string `json:"load_state,omitempty"`
	ActiveState string `json:"active_state,omitempty"`
	SubState    string `json:"sub_state,omitempty"`
	Description string `json:"description,omitempty"`
}

type InventoryProcess struct {
	User    string `json:"user,omitempty"`
	PID     string `json:"pid"`
	CPU     string `json:"cpu,omitempty"`
	Memory  string `json:"memory,omitempty"`
	Command string `json:"command"`
}

type InventoryPort struct {
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Local    string `json:"local"`
	Process  string `json:"process,omitempty"`
}

type InventoryContainer struct {
	Runtime string `json:"runtime"`
	ID      string `json:"id"`
	Image   string `json:"image,omitempty"`
	Name    string `json:"name,omitempty"`
	State   string `json:"state,omitempty"`
}

type WazuhHint struct {
	AgentID      string `json:"agent_id,omitempty"`
	AgentName    string `json:"agent_name,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
}
