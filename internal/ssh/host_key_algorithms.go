package ssh

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyAlgorithmsForKnownHost returns ssh.ClientConfig.HostKeyAlgorithms values
// derived from ~/.ssh/known_hosts lines that apply to host:port. When non-empty,
// the client negotiates those types first so the server picks a host key that
// matches a pinned entry (crypto/ssh's default list prefers ECDSA before Ed25519,
// which often disagrees with OpenSSH and a single-type known_hosts line).
//
// If khPath is missing, unreadable, or has no matching entries, it returns nil, nil.
func HostKeyAlgorithmsForKnownHost(khPath, host, port string) ([]string, error) {
	if khPath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(khPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	want := make(map[string]struct{})
	rest := data
	for len(rest) > 0 {
		marker, hostPatterns, pubKey, _, next, perr := gossh.ParseKnownHosts(rest)
		if errors.Is(perr, io.EOF) {
			break
		}
		if perr != nil {
			return nil, fmt.Errorf("parse known_hosts %q: %w", khPath, perr)
		}
		rest = next

		switch marker {
		case "revoked", "cert-authority":
			continue
		default:
		}
		if pubKey == nil {
			continue
		}
		if !hostPatternsMatch(hostPatterns, host, port) {
			continue
		}
		want[pubKey.Type()] = struct{}{}
	}

	if len(want) == 0 {
		return nil, nil
	}
	return orderHostKeyAlgorithms(want), nil
}

func orderHostKeyAlgorithms(have map[string]struct{}) []string {
	// Preference aligned with OpenSSH: strong modern types before ECDSA/RSA-SHA1.
	pref := []string{
		gossh.CertAlgoED25519v01,
		gossh.KeyAlgoED25519,
		gossh.CertAlgoRSASHA512v01,
		gossh.CertAlgoRSASHA256v01,
		gossh.KeyAlgoRSASHA512,
		gossh.KeyAlgoRSASHA256,
		gossh.CertAlgoECDSA521v01,
		gossh.CertAlgoECDSA384v01,
		gossh.CertAlgoECDSA256v01,
		gossh.KeyAlgoECDSA521,
		gossh.KeyAlgoECDSA384,
		gossh.KeyAlgoECDSA256,
		gossh.CertAlgoRSAv01,
		gossh.KeyAlgoRSA,
		gossh.InsecureCertAlgoDSAv01,
		gossh.InsecureKeyAlgoDSA,
	}
	var out []string
	for _, a := range pref {
		if _, ok := have[a]; ok {
			out = append(out, a)
		}
	}
	for a := range have {
		if !containsString(out, a) {
			out = append(out, a)
		}
	}
	return out
}

func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func hostPatternsMatch(patterns []string, dialHost, dialPort string) bool {
	a := dialAddr{host: dialHost, port: dialPort}
	matched := false
	for _, raw := range patterns {
		p := raw
		negate := false
		if strings.HasPrefix(p, "!") {
			negate = true
			p = p[1:]
		}
		if !singleHostPatternMatches(p, a) {
			continue
		}
		if negate {
			return false
		}
		matched = true
	}
	return matched
}

type dialAddr struct{ host, port string }

func (a dialAddr) stringForHash() string {
	h := a.host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return h + ":" + a.port
}

func singleHostPatternMatches(pat string, a dialAddr) bool {
	if strings.HasPrefix(pat, "|") {
		return hashedHostPatternMatches(pat, a)
	}
	ph, pp, err := net.SplitHostPort(pat)
	if err != nil {
		ph = pat
		pp = "22"
	}
	if pp != a.port {
		return false
	}
	return wildcardMatch([]byte(ph), []byte(a.host))
}

// wildcardMatch follows golang.org/x/crypto/ssh/knownhosts host pattern rules.
func wildcardMatch(pat, str []byte) bool {
	for {
		if len(pat) == 0 {
			return len(str) == 0
		}
		if len(str) == 0 {
			return false
		}
		if pat[0] == '*' {
			if len(pat) == 1 {
				return true
			}
			for j := range str {
				if wildcardMatch(pat[1:], str[j:]) {
					return true
				}
			}
			return false
		}
		if pat[0] == '?' || pat[0] == str[0] {
			pat = pat[1:]
			str = str[1:]
		} else {
			return false
		}
	}
}

func hashedHostPatternMatches(encoded string, a dialAddr) bool {
	typ, salt, hash, err := decodeKnownhostsHash(encoded)
	if err != nil || typ != "1" {
		return false
	}
	norm := knownhosts.Normalize(a.stringForHash())
	got := hashKnownHost(norm, salt)
	return bytes.Equal(got, hash)
}

func decodeKnownhostsHash(encoded string) (hashType string, salt, hash []byte, err error) {
	if len(encoded) == 0 || encoded[0] != '|' {
		return "", nil, nil, errors.New("hashed host must start with '|'")
	}
	components := strings.Split(encoded, "|")
	if len(components) != 4 {
		return "", nil, nil, fmt.Errorf("known_hosts hash: got %d components, want 3 pipes", len(components)-1)
	}
	hashType = components[1]
	salt, err = base64.StdEncoding.DecodeString(components[2])
	if err != nil {
		return "", nil, nil, err
	}
	hash, err = base64.StdEncoding.DecodeString(components[3])
	if err != nil {
		return "", nil, nil, err
	}
	return hashType, salt, hash, nil
}

func hashKnownHost(hostname string, salt []byte) []byte {
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(hostname))
	return mac.Sum(nil)
}
