package cmd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ba0f3/lunacli/internal/config"
	apssh "github.com/ba0f3/lunacli/internal/ssh"
	"github.com/kevinburke/ssh_config"
	"github.com/spf13/cobra"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const sshDebugDialTimeout = 5 * time.Second

var sshDebugCmd = &cobra.Command{
	Use:   "ssh-debug <target>",
	Short: "Diagnose SSH dial, known_hosts, and proxy signing for a target",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSSHDebug(args[0])
	},
}

func init() {
	RootCmd.AddCommand(sshDebugCmd)
}

func runSSHDebug(target string) error {
	fmt.Printf("--- SSH Debug Tool ---\n")
	fmt.Printf("Target: %s\n", target)

	settings, err := config.LoadSettings()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := settings.ValidateTransport(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	pool, err := apssh.NewPool(settings)
	if err != nil {
		return fmt.Errorf("ssh: %w", err)
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

	strict := ssh_config.Get(host, "StrictHostKeyChecking")
	algos := ssh_config.Get(host, "HostKeyAlgorithms")
	fmt.Printf("ssh_config StrictHostKeyChecking: %q\n", strict)
	fmt.Printf("ssh_config HostKeyAlgorithms: %q\n", algos)

	khPath := os.ExpandEnv("$HOME/.ssh/known_hosts")
	fmt.Printf("known_hosts path: %s\n", khPath)

	khCallback, err := knownhosts.New(khPath)
	if err != nil {
		fmt.Printf("Warning: failed to parse known_hosts: %v\n", err)
	} else {
		fmt.Printf("Successfully parsed known_hosts.\n")
	}

	canonical, err := pool.CanonicalTarget(target)
	if err != nil {
		return fmt.Errorf("resolve target: %w", err)
	}
	canonicalT := apssh.TargetFromString(canonical)
	sshUser = canonicalT.User
	addr := net.JoinHostPort(canonicalT.Host, canonicalT.Port)
	dialHost, _ := apssh.ResolveSSHConfigHost(host, port)
	lookupHosts := apssh.KnownHostsLookupCandidates(host, dialHost, canonicalT.Port)
	fmt.Printf("canonical target: %s\n", canonical)
	fmt.Printf("known_hosts lookup hosts: %v\n", lookupHosts)

	fmt.Printf("\nDialing %s as %q...\n", addr, sshUser)

	signers, err := pool.SignersForTarget(context.Background(), target)
	if err != nil {
		return fmt.Errorf("SSH auth: %w", err)
	}

	configDir := settings.ConfigDir()
	fmt.Printf("config dir: %s\n", configDir)

	debugCallback := func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		fmt.Printf("\n[DEBUG] Server presented host key:\n")
		fmt.Printf("  Type: %s\n", key.Type())
		fmt.Printf("  Fingerprint (SHA256): %s\n", gossh.FingerprintSHA256(key))
		fmt.Printf("  Base64: %s\n", base64.StdEncoding.EncodeToString(key.Marshal()))

		var khErr error
		if khCallback != nil {
			for _, lookupHost := range lookupHosts {
				checkAddr := net.JoinHostPort(lookupHost, canonicalT.Port)
				khErr = khCallback(checkAddr, remote, key)
				if khErr == nil {
					break
				}
			}
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
				apssh.BindDestinationHostKey(signers, key)
				return nil
			}
		}

		if ok, invErr := apssh.VerifyHostKeyFromInventory(configDir, host, dialHost, canonicalT.Port, key); invErr != nil {
			return invErr
		} else if ok {
			fmt.Printf("\n[DEBUG] hosts.yml trust: OK (Key matched!)\n")
			apssh.BindDestinationHostKey(signers, key)
			return nil
		}

		if khErr != nil {
			added, promptErr := config.PromptAddHostEntry(os.Stdin, os.Stdout, configDir, host, canonical, key)
			if promptErr != nil {
				return promptErr
			}
			if added {
				apssh.BindDestinationHostKey(signers, key)
				return nil
			}
		}

		return khErr
	}
	authMethods, err := apssh.AuthMethodsFromSigners(host, signers)
	if err != nil {
		return fmt.Errorf("SSH auth: %w", err)
	}
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		fmt.Printf("SSH_AUTH_SOCK: %q\n", sock)
	}
	fmt.Printf("SSH public-key candidates: %d\n", len(signers))

	sshCfg := &gossh.ClientConfig{
		User:            sshUser,
		Auth:            authMethods,
		HostKeyCallback: debugCallback,
		Timeout:         sshDebugDialTimeout,
	}
	if preAlgos, scanErr := apssh.HostKeyAlgorithmsForTarget(configDir, khPath, host, dialHost, canonicalT.Port); scanErr != nil {
		fmt.Printf("Warning: scan known_hosts for host key algorithms: %v\n", scanErr)
	} else if len(preAlgos) > 0 {
		fmt.Printf("HostKeyAlgorithms pinned from known_hosts: %v\n", preAlgos)
		sshCfg.HostKeyAlgorithms = preAlgos
	}

	client, err := gossh.Dial("tcp", addr, sshCfg)
	if err == nil {
		fmt.Printf("Connected.\n")
		defer func() { _ = client.Close() }()
		runSSHDebugProbe(client)
		return nil
	}
	if err.Error() == "debug stop" {
		return nil
	}
	fmt.Printf("Dial error: %v\n", err)

	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) || len(keyErr.Want) == 0 {
		return err
	}

	fmt.Printf("\n[FIX] Automatically retrying with HostKeyAlgorithms restricted to what is known!\n")

	var knownAlgos []string
	for _, w := range keyErr.Want {
		knownAlgos = append(knownAlgos, w.Key.Type())
	}

	fmt.Printf("  Restricting HostKeyAlgorithms to: %v\n", knownAlgos)

	sshCfg.HostKeyAlgorithms = knownAlgos
	sshCfg.HostKeyCallback = func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		if khCallback == nil {
			return nil
		}
		for _, lookupHost := range lookupHosts {
			if err := khCallback(net.JoinHostPort(lookupHost, canonicalT.Port), remote, key); err != nil {
				if ok, invErr := apssh.VerifyHostKeyFromInventory(configDir, host, dialHost, canonicalT.Port, key); invErr == nil && ok {
					apssh.BindDestinationHostKey(signers, key)
					return nil
				}
				if lookupHost == lookupHosts[len(lookupHosts)-1] {
					return err
				}
				continue
			}
			apssh.BindDestinationHostKey(signers, key)
			return nil
		}
		return nil
	}

	client, err = gossh.Dial("tcp", addr, sshCfg)
	if err != nil {
		fmt.Printf("Retry Dial error: %v\n", err)
		return err
	}
	defer func() { _ = client.Close() }()
	fmt.Printf("Retry SUCCESS! Connected using %v\n", knownAlgos)
	runSSHDebugProbe(client)
	return nil
}

func runSSHDebugProbe(client *gossh.Client) {
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
