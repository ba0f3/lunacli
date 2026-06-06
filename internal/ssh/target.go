package ssh

// Target identifies a remote SSH endpoint.
type Target struct {
	User, Host, Port string
	Raw              string
	Alias            string
}

// TargetFromString parses user@host:port using the same rules as the connection pool.
func TargetFromString(raw string) Target {
	u, h, p := parseTarget(raw)
	return Target{User: u, Host: h, Port: p, Raw: raw}
}
