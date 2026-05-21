package config

// ResolveConfigDir returns the directory containing policy.yml and hosts.yml.
// Prefer LoadSettings().ConfigDir() so luna.config.json is honored.
func ResolveConfigDir() string {
	s, err := LoadSettings()
	if err != nil {
		// Fall back to legacy env-only resolution if JSON is malformed.
		return legacyConfigDirFromEnv()
	}
	return s.ConfigDir()
}

func legacyConfigDirFromEnv() string {
	if dir := envFirst("LUNA_CONFIG_DIR", ""); dir != "" {
		return dir
	}
	s := &Settings{}
	return s.ConfigDir()
}
