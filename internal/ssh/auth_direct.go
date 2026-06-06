package ssh

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/kevinburke/ssh_config"
	gossh "golang.org/x/crypto/ssh"
)

type directAuth struct{}

func (d *directAuth) SignersFor(ctx context.Context, t Target) ([]gossh.Signer, error) {
	_ = ctx
	return collectAuthSigners(t.Host)
}

// collectAuthSigners returns distinct signers for host. Order matters: ssh-agent
// keys first (common with Bitwarden/1Password agents), then ssh_config IdentityFile
// entries, then default ~/.ssh/id_* files.
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
