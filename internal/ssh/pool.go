package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"strings"
	"sync"
	"time"

	"github.com/ba0f3/lunacli/internal/config"
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
	mu        sync.Mutex
	clients   map[string]*gossh.Client
	auth      AuthProvider
	configDir string
	hostTrust hostTrustGate
}

type hostTrustGate interface {
	WaitTrustHostApproval(ctx context.Context, alias, hostTarget, canonicalHost, configDir string, pub gossh.PublicKey) error
}

// SetHostTrustGate wires Telegram/out-of-band host-trust approval for luna serve.
func (p *Pool) SetHostTrustGate(g hostTrustGate) {
	if p == nil {
		return
	}
	p.hostTrust = g
}

// ConfigDir returns the Luna config directory (policy.yml / hosts.yml), if any.
func (p *Pool) ConfigDir() string {
	if p == nil {
		return ""
	}
	return p.configDir
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

// NewPool creates a new SSH connection pool with direct (legacy) auth when cfg is nil.
func NewPool(cfg *config.Settings) (*Pool, error) {
	auth, err := NewAuthProvider(cfg)
	if err != nil {
		return nil, err
	}
	if cfg != nil {
		log.Printf("[SSH] transport.mode=%s", cfg.TransportMode())
	}
	var configDir string
	if cfg != nil {
		configDir = cfg.ConfigDir()
	}
	return &Pool{
		clients:   make(map[string]*gossh.Client),
		auth:      auth,
		configDir: configDir,
	}, nil
}

func (p *Pool) signersFor(ctx context.Context, target string) ([]gossh.Signer, error) {
	t, err := canonicalTarget(target)
	if err != nil {
		return nil, err
	}
	return p.auth.SignersFor(ctx, t)
}

// SignersForTarget returns SSH signers for target (used by ssh-debug).
func (p *Pool) SignersForTarget(ctx context.Context, target string) ([]gossh.Signer, error) {
	return p.signersFor(ctx, target)
}

// CanonicalTarget resolves SSH config aliases and DNS to the exact user, IP, and
// port used for proxy authorization and dialing.
func (p *Pool) CanonicalTarget(target string) (string, error) {
	resolved, err := canonicalTarget(target)
	if err != nil {
		return "", err
	}
	return resolved.Raw, nil
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
	return p.execute(target, "", command, timeout)
}

// ExecuteBound runs command through the original SSH alias while requiring the
// exact canonical target previously used for policy and approval.
func (p *Pool) ExecuteBound(target, canonicalTarget, command string, timeout time.Duration) (ExecResult, error) {
	return p.execute(target, canonicalTarget, command, timeout)
}

func (p *Pool) execute(target, boundTarget, command string, timeout time.Duration) (ExecResult, error) {
	client, err := p.getClientBound(target, boundTarget)
	if err != nil {
		return ExecResult{}, err
	}

	session, err := client.NewSession()
	if err != nil {
		p.evict(connectionCacheKey(target, boundTarget))
		client, err = p.getClientBound(target, boundTarget)
		if err != nil {
			return ExecResult{}, err
		}
		session, err = client.NewSession()
		if err != nil {
			return ExecResult{}, fmt.Errorf("create SSH session: %w", err)
		}
	}
	defer func() { _ = session.Close() }()

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
	return p.getClientBound(target, "")
}

func (p *Pool) getClientBound(target, boundTarget string) (*gossh.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	cacheKey := connectionCacheKey(target, boundTarget)
	if c, ok := p.clients[cacheKey]; ok {
		if _, _, err := c.SendRequest("keepalive@openssh.com", true, nil); err == nil {
			return c, nil
		}
		c.Close() //nolint:errcheck
		delete(p.clients, cacheKey)
	}

	username, host, port := parseTarget(target)
	dialHost, _ := resolveSSHConfigHost(host, port)
	var canonical Target
	var err error
	if boundTarget == "" {
		canonical, err = canonicalTarget(target)
		if err != nil {
			return nil, err
		}
	} else {
		canonical = TargetFromString(boundTarget)
		if net.ParseIP(canonical.Host) == nil {
			return nil, fmt.Errorf("bound SSH target must contain an IP address: %q", boundTarget)
		}
		canonical.Raw = fmt.Sprintf("%s@%s", canonical.User, net.JoinHostPort(canonical.Host, canonical.Port))
		canonical.Alias = host
	}
	username = canonical.User
	addr := net.JoinHostPort(canonical.Host, canonical.Port)

	signers, err := p.auth.SignersFor(context.Background(), canonical)
	if err != nil {
		return nil, fmt.Errorf("build auth for %q: %w", target, err)
	}
	logSSHAuthDialPrep(target, username, addr, signers)

	authMethods, err := authMethodsFromSigners(host, signers)
	if err != nil {
		return nil, fmt.Errorf("build auth for %q: %w", target, err)
	}

	khCallback, err := buildKnownHostsCallback(p.configDir, p.hostTrust, host, dialHost, canonical.Port, target, canonical.Raw, func(key gossh.PublicKey) {
		setDestinationHostKey(signers, key)
	})
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}

	khPath := fmt.Sprintf("%s/.ssh/known_hosts", mustHome())
	hostKeyAlgos, err := HostKeyAlgorithmsForTarget(p.configDir, khPath, host, dialHost, canonical.Port)
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

	p.clients[cacheKey] = client
	return client, nil
}

func connectionCacheKey(target, boundTarget string) string {
	if boundTarget == "" {
		return target
	}
	return target + "\x00" + boundTarget
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
	fixed := signers
	return []gossh.AuthMethod{gossh.PublicKeysCallback(func() ([]gossh.Signer, error) {
		return fixed, nil
	})}, nil
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

// DialAuthMethods returns SSH client auth methods using direct-mode key collection.
// Pass the ssh Host alias or hostname used for IdentityFile lookups (same as DialTarget host).
func DialAuthMethods(host string) ([]gossh.AuthMethod, error) {
	return buildAuthMethods(host)
}

// AuthMethodsFromSigners builds auth methods from pre-resolved signers (same as the pool uses).
func AuthMethodsFromSigners(host string, signers []gossh.Signer) ([]gossh.AuthMethod, error) {
	return authMethodsFromSigners(host, signers)
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

// buildKnownHostsCallback creates a host key callback from ~/.ssh/known_hosts and
// hosts.yml (secondary) that respects ~/.ssh/config StrictHostKeyChecking settings.
func buildKnownHostsCallback(configDir string, hostTrust hostTrustGate, sshAlias, dialHost, khPort, hostTarget, canonicalTarget string, accepted func(gossh.PublicKey)) (gossh.HostKeyCallback, error) {
	khPath := fmt.Sprintf("%s/.ssh/known_hosts", mustHome())
	lookupHosts := knownHostsLookupCandidates(sshAlias, dialHost, khPort)

	var khCallback gossh.HostKeyCallback
	if _, err := os.Stat(khPath); !os.IsNotExist(err) {
		cb, err := knownhosts.New(khPath)
		if err != nil {
			return nil, fmt.Errorf("parse known_hosts: %w", err)
		}
		khCallback = cb
	}

	return func(_ string, remote net.Addr, key gossh.PublicKey) error {
		var checkErr error
		if khCallback != nil {
			for _, lookupHost := range lookupHosts {
				checkAddr := knownHostsCheckAddress(lookupHost, khPort)
				checkErr = khCallback(checkAddr, remote, key)
				if checkErr == nil {
					if accepted != nil {
						accepted(key)
					}
					return nil
				}
			}
		} else {
			checkErr = fmt.Errorf("known_hosts file not found")
		}

		if ok, err := VerifyHostKeyFromInventory(configDir, sshAlias, dialHost, khPort, key); err != nil {
			return err
		} else if ok {
			if accepted != nil {
				accepted(key)
			}
			return nil
		}

		// Read StrictHostKeyChecking for the target host
		strict := strings.ToLower(ssh_config.Get(sshAlias, "StrictHostKeyChecking"))

		if strict == "no" || strict == "false" {
			log.Printf("WARN: bypassing host key check for %s due to StrictHostKeyChecking=%s", sshAlias, strict)
			if accepted != nil {
				accepted(key)
			}
			return nil
		}

		if strict == "accept-new" {
			var keyErr *knownhosts.KeyError
			if errors.As(checkErr, &keyErr) {
				// If Want is empty, there were NO keys for this host (completely new).
				if len(keyErr.Want) == 0 {
					return fmt.Errorf("StrictHostKeyChecking=accept-new is unsupported because lunacli cannot persist the accepted key; use ssh %s once to add it", sshAlias)
				}
			} else if checkErr.Error() == "known_hosts file not found" {
				return fmt.Errorf("StrictHostKeyChecking=accept-new is unsupported because lunacli cannot persist the accepted key; use ssh %s once to add it", sshAlias)
			}
		}

		if hostTrust != nil && configDir != "" {
			log.Printf("[SSH] host %q unknown; waiting for host-trust approval via Telegram", sshAlias)
			if err := hostTrust.WaitTrustHostApproval(context.Background(), sshAlias, hostTarget, canonicalTarget, configDir, key); err != nil {
				log.Printf("[SSH] host-trust approval for %q: %v", sshAlias, err)
			} else {
				if accepted != nil {
					accepted(key)
				}
				return nil
			}
		}

		if isInteractiveStdin() && configDir != "" {
			hostLine := canonicalTarget
			if hostLine == "" {
				hostLine = hostTarget
			}
			added, promptErr := config.PromptAddHostEntry(os.Stdin, os.Stderr, configDir, sshAlias, hostLine, key)
			if promptErr != nil {
				return promptErr
			}
			if added {
				if accepted != nil {
					accepted(key)
				}
				return nil
			}
		}

		// Provide a more helpful error message
		if checkErr != nil {
			hint := inventoryTrustHint(configDir, sshAlias)
			if hostTrust != nil {
				hint += "; approve host trust in Telegram when prompted during dial"
			}
			if strict == "ask" || strict == "" {
				return fmt.Errorf("%w (StrictHostKeyChecking=%s; %s)", checkErr, strict, hint)
			}
			return fmt.Errorf("%w (%s)", checkErr, hint)
		}

		return nil
	}, nil
}

func isInteractiveStdin() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func setDestinationHostKey(signers []gossh.Signer, key gossh.PublicKey) {
	for _, signer := range signers {
		if hosted, ok := signer.(*hostedKeySigner); ok {
			hosted.setDestinationHostKey(key)
		}
	}
}

// BindDestinationHostKey records the verified SSH server host key on local-key
// signers. Must run from HostKeyCallback before user authentication begins.
func BindDestinationHostKey(signers []gossh.Signer, key gossh.PublicKey) {
	setDestinationHostKey(signers, key)
}

func mustHome() string {
	h, _ := os.UserHomeDir()
	return h
}
