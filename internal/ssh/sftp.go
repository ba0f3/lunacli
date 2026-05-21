package ssh

import (
	"fmt"

	"github.com/pkg/sftp"
)

// ReadFile fetches up to maxBytes of a remote file via SFTP.
// A new SFTP session is opened for each call and closed immediately after.
func (p *Pool) ReadFile(alias, path string, maxBytes int64) ([]byte, error) {
	client, err := p.getClient(alias)
	if err != nil {
		return nil, err
	}

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return nil, fmt.Errorf("open SFTP session on %s: %w", alias, err)
	}
	defer sftpClient.Close()

	f, err := sftpClient.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %q on %s: %w", path, alias, err)
	}
	defer f.Close()

	buf := make([]byte, maxBytes)
	n, readErr := f.Read(buf)
	// io.EOF is expected at end of file — not an error.
	if readErr != nil && readErr.Error() != "EOF" {
		return nil, fmt.Errorf("read %q on %s: %w", path, alias, readErr)
	}
	return buf[:n], nil
}

// WriteFile uploads content to a remote path via SFTP with the given permissions.
func (p *Pool) WriteFile(alias, path string, content []byte, permissions string) error {
	client, err := p.getClient(alias)
	if err != nil {
		return err
	}

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("open SFTP session on %s: %w", alias, err)
	}
	defer sftpClient.Close()

	f, err := sftpClient.Create(path)
	if err != nil {
		return fmt.Errorf("create %q on %s: %w", path, alias, err)
	}
	defer f.Close()

	if _, err := f.Write(content); err != nil {
		return fmt.Errorf("write %q on %s: %w", path, alias, err)
	}

	// Apply permissions if specified (e.g. "0644").
	if permissions != "" {
		var mode uint32
		if _, err := fmt.Sscanf(permissions, "%o", &mode); err == nil {
			_ = sftpClient.Chmod(path, fileMode(mode))
		}
	}

	return nil
}
