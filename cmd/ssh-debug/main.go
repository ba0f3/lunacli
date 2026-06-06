package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ba0f3/lunacli/internal/config"
	apssh "github.com/ba0f3/lunacli/internal/ssh"
	"github.com/kevinburke/ssh_config"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func runRemoteProbe(client *gossh.Client) {
	session, err := client.NewSession()
	if err != nil {
		fmt.Printf("NewSession: %v\n", err)
		return
	}
	defer func() { _ = session.Close() }()
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	fmt.Printf("\n--- exec: hostname && uptime ---\n")
	if err := session.Run("hostname && uptime"); err != nil {
		fmt.Printf("session.Run: %v\n", err)
	}
}

func main() {
	flag.Parse()
	target := flag.Arg(0)
	if target == "" {
		log.Fatalf("Usage: ssh-debug <target>")
	}

	fmt.Printf("--- SSH Debug Tool ---\n")
	fmt.Printf("Target: %s\n", target)

	settings, err := config.LoadSettings()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := settings.ValidateTransport(); err != nil {
		log.Fatalf("config: %v", err)
	}
	pool, err := apssh.NewPool(settings)
	if err != nil {
		log.Fatalf("ssh: %v", err)
	}
	fmt.Printf("transport.mode: %s\n", settings.TransportMode())
	if ep := settings.ProxyEndpoint(); ep != "" {
		fmt.Printf("transport.proxy.endpoint: %s\n", ep)
	}

	sshUser, host, port := apssh.DialTarget(target)
	if !strings.Contains(target, "@") {
		if cfg := strings.TrimSpace(ssh_config.Get(host, "User")); cfg != "" {
			sshUser = cfg
		}
	}

	// 1. Read ssh_config (by literal hostname / IP passed for dialing)
	strict := ssh_config.Get(host, "StrictHostKeyChecking")
	algos := ssh_config.Get(host, "HostKeyAlgorithms")
	fmt.Printf("ssh_config StrictHostKeyChecking: %q\n", strict)
	fmt.Printf("ssh_config HostKeyAlgorithms: %q\n", algos)

	// 2. Setup knownhosts
	khPath := os.ExpandEnv("$HOME/.ssh/known_hosts")
	fmt.Printf("known_hosts path: %s\n", khPath)

	khCallback, err := knownhosts.New(khPath)
	if err != nil {
		fmt.Printf("Warning: failed to parse known_hosts: %v\n", err)
	} else {
		fmt.Printf("Successfully parsed known_hosts.\n")
	}

	// 3. Setup our debug callback
	debugCallback := func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		fmt.Printf("\n[DEBUG] Server presented host key:\n")
		fmt.Printf("  Type: %s\n", key.Type())
		fmt.Printf("  Fingerprint (SHA256): %s\n", gossh.FingerprintSHA256(key))
		fmt.Printf("  Base64: %s\n", base64.StdEncoding.EncodeToString(key.Marshal()))

		var khErr error
		if khCallback != nil {
			khErr = khCallback(hostname, remote, key)
			if khErr != nil {
				fmt.Printf("\n[DEBUG] knownhosts.New callback result: %v\n", khErr)

				var keyErr *knownhosts.KeyError
				if errors.As(khErr, &keyErr) {
					fmt.Printf("  KeyError Details:\n")
					fmt.Printf("  Want:\n")
					for _, w := range keyErr.Want {
						fmt.Printf("    - Type: %s, Fingerprint: %s\n", w.Key.Type(), gossh.FingerprintSHA256(w.Key))
					}
					if len(keyErr.Want) == 0 {
						fmt.Printf("    - (No keys found for this host in known_hosts)\n")
					}
				}
			} else {
				fmt.Printf("\n[DEBUG] knownhosts.New callback result: OK (Key matched!)\n")
			}
		}

		return khErr
	}

	// 4. Dial
	addr := net.JoinHostPort(host, port)
	fmt.Printf("\nDialing %s as %q...\n", addr, sshUser)

	signers, authErr := pool.SignersForTarget(context.Background(), target)
	if authErr != nil {
		log.Fatalf("SSH auth: %v", authErr)
	}
	authMethods, authErr := apssh.AuthMethodsFromSigners(host, signers)
	if authErr != nil {
		log.Fatalf("SSH auth: %v", authErr)
	}
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		fmt.Printf("SSH_AUTH_SOCK: %q\n", sock)
	}
	fmt.Printf("SSH public-key candidates: %d\n", len(signers))

	config := &gossh.ClientConfig{
		User:            sshUser,
		Auth:            authMethods,
		HostKeyCallback: debugCallback,
		Timeout:         5 * time.Second,
	}
	if preAlgos, scanErr := apssh.HostKeyAlgorithmsForKnownHost(khPath, host, port); scanErr != nil {
		fmt.Printf("Warning: scan known_hosts for host key algorithms: %v\n", scanErr)
	} else if len(preAlgos) > 0 {
		fmt.Printf("HostKeyAlgorithms pinned from known_hosts: %v\n", preAlgos)
		config.HostKeyAlgorithms = preAlgos
	}

	client, err := gossh.Dial("tcp", addr, config)
	if err == nil {
		fmt.Printf("Connected.\n")
		defer func() { _ = client.Close() }()
		runRemoteProbe(client)
		return
	}
	if err.Error() == "debug stop" {
		return
	}
	fmt.Printf("Dial error: %v\n", err)

	// Fallback: algorithm mismatch if scan missed (e.g. parse error) or handshake wraps errors oddly.
	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) || len(keyErr.Want) == 0 {
		os.Exit(1)
	}

	fmt.Printf("\n[FIX] Automatically retrying with HostKeyAlgorithms restricted to what is known!\n")

	var knownAlgos []string
	for _, w := range keyErr.Want {
		knownAlgos = append(knownAlgos, w.Key.Type())
	}

	fmt.Printf("  Restricting HostKeyAlgorithms to: %v\n", knownAlgos)

	config.HostKeyAlgorithms = knownAlgos
	config.HostKeyCallback = khCallback

	client, err = gossh.Dial("tcp", addr, config)
	if err != nil {
		fmt.Printf("Retry Dial error: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = client.Close() }()
	fmt.Printf("Retry SUCCESS! Connected using %v\n", knownAlgos)
	runRemoteProbe(client)
}
