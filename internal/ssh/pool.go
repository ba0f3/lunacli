package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kevinburke/ssh_config"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ExecResult holds the output of a remote command execution.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

// Pool manages a cache of SSH client connections.
// Connections are established lazily and reused across calls.
type Pool struct {
	mu      sync.Mutex
	clients map[string]*gossh.Client
}

// sharedAgent holds one ssh-agent connection for the process. Agent-backed
// Signers call back into this client during SSH auth; closing the connection
// when listing keys (e.g. defer conn.Close() before auth completes) breaks
// signing with "use of closed network connection".
var sharedAgent struct {
	mu     sync.Mutex
	sock   string
	conn   net.Conn
	client agent.ExtendedAgent
}

// sshAgentIssueLogged dedupes agent diagnostics: PublicKeysCallback may call
// collectAuthSigners many times during one handshake; stderr must stay MCP-safe
// (no flood) while still surfacing misconfigured MCP environments (missing/wrong SSH_AUTH_SOCK).
var sshAgentIssueLogged sync.Map // string (message) -> struct{}

func logSSHAgentIssueOnce(msg string) {
	if _, loaded := sshAgentIssueLogged.LoadOrStore(msg, true); !loaded {
		log.Print(msg)
	}
}

func sharedAgentSigners() ([]gossh.Signer, error) {
	sock := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	if sock == "" {
		return nil, nil
	}

	sharedAgent.mu.Lock()
	defer sharedAgent.mu.Unlock()

	if sharedAgent.client != nil && sharedAgent.sock == sock {
		return sharedAgent.client.Signers()
	}

	if sharedAgent.conn != nil {
		_ = sharedAgent.conn.Close()
		sharedAgent.conn = nil
		sharedAgent.client = nil
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		logSSHAgentIssueOnce(fmt.Sprintf("[SSH] ssh-agent: cannot dial SSH_AUTH_SOCK=%q: %v (agent keys skipped; disk IdentityFile/id_* may still be used)", sock, err))
		return nil, nil
	}
	ac := agent.NewClient(conn)
	signers, err := ac.Signers()
	if err != nil {
		_ = conn.Close()
		logSSHAgentIssueOnce(fmt.Sprintf("[SSH] ssh-agent: list keys on %q failed: %v (agent keys skipped)", sock, err))
		return nil, nil
	}
	sharedAgent.sock = sock
	sharedAgent.conn = conn
	sharedAgent.client = ac
	return signers, nil
}

func closeSharedAgent() {
	sharedAgent.mu.Lock()
	defer sharedAgent.mu.Unlock()
	if sharedAgent.conn != nil {
		_ = sharedAgent.conn.Close()
	}
	sharedAgent.conn = nil
	sharedAgent.client = nil
	sharedAgent.sock = ""
}

// NewPool creates a new SSH connection pool.
func NewPool() *Pool {
	return &Pool{
		clients: make(map[string]*gossh.Client),
	}
}

// parseTarget splits a target string like user@host:port into its components.
// It matches OpenSSH behavior: if no explicit user@ prefix is given, it
// consults ~/.ssh/config User directive (e.g. Host * User root) before
// falling back to the current OS user.
func parseTarget(target string) (username, host, port string) {
	username = "root"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}
	port = "22"
	host = target

	hasExplicitUser := false
	if idx := strings.Index(host, "@"); idx != -1 {
		username = host[:idx]
		host = host[idx+1:]
		hasExplicitUser = true
	}

	if strings.Contains(host, ":") {
		h, p, err := net.SplitHostPort(host)
		if err == nil {
			host = h
			port = p
		}
	}

	// No explicit user@ prefix: consult ~/.ssh/config User directive
	// for the resolved host (e.g. "Host * User root").
	if !hasExplicitUser {
		if cfgUser := ssh_config.Get(host, "User"); cfgUser != "" {
			username = cfgUser
		}
	}

	return username, host, port
}

// DialTarget splits user@host:port the same way as the connection pool.
func DialTarget(target string) (username, host, port string) {
	return parseTarget(target)
}

// Execute runs command on the named target and returns the result.
func (p *Pool) Execute(target, command string, timeout time.Duration) (ExecResult, error) {
	client, err := p.getClient(target)
	if err != nil {
		return ExecResult{}, err
	}

	session, err := client.NewSession()
	if err != nil {
		p.evict(target)
		client, err = p.getClient(target)
		if err != nil {
			return ExecResult{}, err
		}
		session, err = client.NewSession()
		if err != nil {
			return ExecResult{}, fmt.Errorf("create SSH session: %w", err)
		}
	}
	defer session.Close()

	var stdoutBuf, stderrBuf strings.Builder
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	start := time.Now()

	type result struct {
		err      error
		exitCode int
	}
	ch := make(chan result, 1)
	go func() {
		runErr := session.Run(command)
		code := 0
		if runErr != nil {
			if exitErr, ok := runErr.(*gossh.ExitError); ok {
				code = exitErr.ExitStatus()
				runErr = nil
			}
		}
		ch <- result{err: runErr, exitCode: code}
	}()

	select {
	case res := <-ch:
		dur := time.Since(start)
		if res.err != nil {
			return ExecResult{}, fmt.Errorf("SSH run: %w", res.err)
		}
		return ExecResult{
			Stdout:   stdoutBuf.String(),
			Stderr:   stderrBuf.String(),
			ExitCode: res.exitCode,
			Duration: dur,
		}, nil
	case <-time.After(timeout):
		session.Signal(gossh.SIGKILL) //nolint:errcheck
		return ExecResult{ExitCode: -1}, fmt.Errorf("command timed out after %s", timeout)
	}
}

// getClient returns a cached or newly-dialed client for the given target.
func (p *Pool) getClient(target string) (*gossh.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if c, ok := p.clients[target]; ok {
		if _, _, err := c.SendRequest("keepalive@openssh.com", true, nil); err == nil {
			return c, nil
		}
		c.Close() //nolint:errcheck
		delete(p.clients, target)
	}

	username, host, port := parseTarget(target)
	addr := net.JoinHostPort(host, port)

	signers, err := collectAuthSigners(host)
	if err != nil {
		return nil, fmt.Errorf("build auth for %q: %w", target, err)
	}
	logSSHAuthDialPrep(target, username, addr, signers)

	authMethods, err := authMethodsFromSigners(host, signers)
	if err != nil {
		return nil, fmt.Errorf("build auth for %q: %w", target, err)
	}

	khCallback, err := buildKnownHostsCallback(host)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}

	khPath := fmt.Sprintf("%s/.ssh/known_hosts", mustHome())
	hostKeyAlgos, err := HostKeyAlgorithmsForKnownHost(khPath, host, port)
	if err != nil {
		log.Printf("[SSH] known_hosts host-key algorithm scan for %s: %v (using crypto/ssh defaults)", host, err)
	}

	sshCfg := &gossh.ClientConfig{
		User:            username,
		Auth:            authMethods,
		HostKeyCallback: khCallback,
		Timeout:         15 * time.Second,
	}
	if len(hostKeyAlgos) > 0 {
		sshCfg.HostKeyAlgorithms = hostKeyAlgos
	}

	log.Printf("[SSH] connecting to %s@%s (StrictHostKeyChecking: %s)", username, addr, ssh_config.Get(host, "StrictHostKeyChecking"))
	client, err := gossh.Dial("tcp", addr, sshCfg)
	if err != nil {
		log.Printf("[SSH] Dial failed for %s: %v", target, err)
		// Fix for Go x/crypto/ssh algorithm mismatch: if the server presented an unexpected key algorithm,
		// but we know the correct algorithms from known_hosts, retry restricting HostKeyAlgorithms.
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) && len(keyErr.Want) > 0 {
			var knownAlgos []string
			for _, w := range keyErr.Want {
				knownAlgos = append(knownAlgos, w.Key.Type())
			}
			log.Printf("[SSH] host key algorithm mismatch for %s. Server sent %s, but we only have %v in known_hosts. Retrying explicitly with those algorithms.", target, keyErr.Want[0].Key.Type(), knownAlgos)

			sshCfg.HostKeyAlgorithms = knownAlgos
			client, err = gossh.Dial("tcp", addr, sshCfg)
			if err != nil {
				log.Printf("[SSH] Retry Dial failed for %s: %v", target, err)
				logSSHAuthDialFailure(signers, err)
				return nil, fmt.Errorf("dial %s (after algorithm retry): %w", target, err)
			}
			log.Printf("[SSH] Retry SUCCESS for %s using %v", target, knownAlgos)
		} else {
			logSSHAuthDialFailure(signers, err)
			return nil, fmt.Errorf("dial %s: %w", target, err)
		}
	} else {
		log.Printf("[SSH] Connection established to %s", target)
	}

	p.clients[target] = client
	return client, nil
}

// evict removes a target's cached client without closing it.
func (p *Pool) evict(target string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.clients, target)
}

// Close shuts down all cached connections.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for alias, c := range p.clients {
		if err := c.Close(); err != nil {
			log.Printf("close %s: %v", alias, err)
		}
	}
	p.clients = make(map[string]*gossh.Client)
	closeSharedAgent()
}

// expandIdentityFilePath expands ~/.ssh/foo and optional double-quotes from ssh_config.
func expandIdentityFilePath(raw string) string {
	p := strings.TrimSpace(raw)
	if len(p) >= 2 && p[0] == '"' && p[len(p)-1] == '"' {
		p = p[1 : len(p)-1]
	}
	if p == "" || p == "/dev/null" {
		return ""
	}
	if strings.HasPrefix(p, "~/") {
		p = filepath.Join(mustHome(), p[2:])
	} else if p == "~" {
		p = mustHome()
	}
	return os.ExpandEnv(p)
}

// collectAuthSigners returns distinct signers for host. Order matters: ssh-agent
// keys first (common with Bitwarden/1Password agents), then ssh_config IdentityFile
// entries, then default ~/.ssh/id_* files. Putting many disk keys before the agent
// can exhaust the server's MaxAuthTries before an agent-only identity is tried.
func collectAuthSigners(host string) ([]gossh.Signer, error) {
	host = strings.TrimSpace(host)
	var out []gossh.Signer
	seen := make(map[string]struct{})

	add := func(s gossh.Signer) {
		if s == nil {
			return
		}
		k := string(s.PublicKey().Marshal())
		if _, dup := seen[k]; dup {
			return
		}
		seen[k] = struct{}{}
		out = append(out, s)
	}

	ag, _ := sharedAgentSigners()
	for _, s := range ag {
		add(s)
	}

	if host != "" {
		idFiles := ssh_config.GetAll(host, "IdentityFile")
		certFiles := ssh_config.GetAll(host, "CertificateFile")
		for i, raw := range idFiles {
			path := expandIdentityFilePath(raw)
			if path == "" {
				continue
			}
			st, err := os.Stat(path)
			if err != nil || st.IsDir() {
				continue
			}
			if signer, err := loadPrivateKey(path); err == nil {
				optCert := ""
				if i < len(certFiles) {
					optCert = expandIdentityFilePath(certFiles[i])
				}
				add(tryWrapWithCertificate(path, optCert, signer))
			}
		}
	}

	for _, name := range []string{"id_ed25519", "id_rsa", "id_ecdsa"} {
		path := filepath.Join(mustHome(), ".ssh", name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if signer, err := loadPrivateKey(path); err == nil {
			add(tryWrapWithCertificate(path, "", signer))
		}
	}

	return out, nil
}

// AuthSignerCount returns how many distinct public keys would be offered for host
// (for diagnostics). It performs the same collection as DialAuthMethods.
func AuthSignerCount(host string) (int, error) {
	s, err := collectAuthSigners(host)
	return len(s), err
}

// buildAuthMethods returns a single publickey AuthMethod whose callback merges
// SSH_AUTH_SOCK agent keys, ssh_config IdentityFile entries, and default ~/.ssh/id_*.
// crypto/ssh only runs the first "publickey" entry in ClientConfig.Auth; multiple
// separate PublicKeys/PublicKeysCallback methods would hide later keys.
func buildAuthMethods(host string) ([]gossh.AuthMethod, error) {
	signers, err := collectAuthSigners(host)
	if err != nil {
		return nil, err
	}
	return authMethodsFromSigners(host, signers)
}

func authMethodsFromSigners(host string, signers []gossh.Signer) ([]gossh.AuthMethod, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("no SSH auth methods available (no agent, no default keys)")
	}
	merged := func() ([]gossh.Signer, error) {
		return collectAuthSigners(host)
	}
	return []gossh.AuthMethod{gossh.PublicKeysCallback(merged)}, nil
}

func logSSHAuthDialPrep(target, username, addr string, signers []gossh.Signer) {
	sock := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	sockDesc := "(unset — agent keys unavailable; set SSH_AUTH_SOCK for desktop agents e.g. Bitwarden/1Password)"
	if sock != "" {
		sockDesc = sock
	}
	log.Printf("[SSH] auth prep target=%q user=%s addr=%s HOME=%s SSH_AUTH_SOCK=%s signer_count=%d keys=%s",
		target, username, addr, mustHome(), sockDesc, len(signers), signerKeySummaries(signers))
}

func logSSHAuthDialFailure(signers []gossh.Signer, dialErr error) {
	if dialErr == nil {
		return
	}
	msg := dialErr.Error()
	if strings.Contains(msg, "unable to authenticate") || strings.Contains(msg, "no supported methods remain") {
		log.Printf("[SSH] userauth failed; offered keys were: %s", signerKeySummaries(signers))
	}
}

func signerKeySummaries(signers []gossh.Signer) string {
	if len(signers) == 0 {
		return "(none)"
	}
	const max = 12
	var b strings.Builder
	for i, s := range signers {
		if i >= max {
			fmt.Fprintf(&b, "; …+%d more", len(signers)-max)
			break
		}
		if i > 0 {
			b.WriteString("; ")
		}
		pub := s.PublicKey()
		fmt.Fprintf(&b, "%s SHA256:%s", pub.Type(), gossh.FingerprintSHA256(pub))
	}
	return b.String()
}

// DialAuthMethods returns the same SSH client auth methods as the connection pool.
// Pass the ssh Host alias or hostname used for IdentityFile lookups (same as DialTarget host).
func DialAuthMethods(host string) ([]gossh.AuthMethod, error) {
	return buildAuthMethods(host)
}

// loadPrivateKey reads and parses a PEM-encoded private key file.
func loadPrivateKey(path string) (gossh.Signer, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key %q: %w", path, err)
	}
	signer, err := gossh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("parse key %q: %w", path, err)
	}
	return signer, nil
}

// tryWrapWithCertificate returns a CertSigner if certPathOptional or path-cert.pub
// contains an SSH user certificate for the same public key as signer; otherwise signer.
func tryWrapWithCertificate(privKeyPath, certPathOptional string, signer gossh.Signer) gossh.Signer {
	if signer == nil {
		return nil
	}
	var candidates []string
	if cp := strings.TrimSpace(certPathOptional); cp != "" {
		candidates = append(candidates, cp)
	}
	candidates = append(candidates, privKeyPath+"-cert.pub")
	for _, cp := range candidates {
		if cp == "" {
			continue
		}
		data, err := os.ReadFile(cp)
		if err != nil {
			continue
		}
		pub, err := gossh.ParsePublicKey(data)
		if err != nil {
			continue
		}
		cert, ok := pub.(*gossh.Certificate)
		if !ok {
			continue
		}
		if !bytes.Equal(cert.Key.Marshal(), signer.PublicKey().Marshal()) {
			continue
		}
		if cs, err := gossh.NewCertSigner(cert, signer); err == nil {
			return cs
		}
	}
	return signer
}

// buildKnownHostsCallback creates a host key callback from ~/.ssh/known_hosts
// that respects ~/.ssh/config StrictHostKeyChecking settings (no, accept-new).
func buildKnownHostsCallback(targetHost string) (gossh.HostKeyCallback, error) {
	khPath := fmt.Sprintf("%s/.ssh/known_hosts", mustHome())

	var khCallback gossh.HostKeyCallback
	if _, err := os.Stat(khPath); !os.IsNotExist(err) {
		cb, err := knownhosts.New(khPath)
		if err != nil {
			return nil, fmt.Errorf("parse known_hosts: %w", err)
		}
		khCallback = cb
	}

	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		var checkErr error
		if khCallback != nil {
			checkErr = khCallback(hostname, remote, key)
			if checkErr == nil {
				return nil
			}
		} else {
			checkErr = fmt.Errorf("known_hosts file not found")
		}

		// Read StrictHostKeyChecking for the target host
		strict := strings.ToLower(ssh_config.Get(targetHost, "StrictHostKeyChecking"))

		if strict == "no" || strict == "false" {
			log.Printf("WARN: bypassing host key check for %s due to StrictHostKeyChecking=%s", targetHost, strict)
			return nil
		}

		if strict == "accept-new" {
			var keyErr *knownhosts.KeyError
			if errors.As(checkErr, &keyErr) {
				// If Want is empty, there were NO keys for this host (completely new).
				if len(keyErr.Want) == 0 {
					log.Printf("INFO: auto-accepting new host key for %s due to StrictHostKeyChecking=accept-new", targetHost)
					return nil
				}
			} else if checkErr.Error() == "known_hosts file not found" {
				log.Printf("INFO: auto-accepting new host key for %s because known_hosts is missing", targetHost)
				return nil
			}
		}

		// Provide a more helpful error message
		if checkErr != nil {
			if strict == "ask" || strict == "" {
				return fmt.Errorf("%w (StrictHostKeyChecking=%s, use 'ssh %s' to accept or set accept-new in config)", checkErr, strict, targetHost)
			}
			return fmt.Errorf("%w", checkErr)
		}

		return nil
	}, nil
}

func mustHome() string {
	h, _ := os.UserHomeDir()
	return h
}
