package policy

type CommandRule struct {
	Binary     string   `yaml:"binary"`
	ArgsPrefix []string `yaml:"args_prefix"`
}

type Rule struct {
	Action   string        `yaml:"action"` // allow, approve, deny
	Hosts    []string      `yaml:"hosts"`
	Tags     []string      `yaml:"tags"`
	Commands []CommandRule `yaml:"commands"`
}

type Policy struct {
	Version      int      `yaml:"version"`
	DenyPatterns []string `yaml:"deny_patterns"`
	Rules        []Rule   `yaml:"rules"`
}
