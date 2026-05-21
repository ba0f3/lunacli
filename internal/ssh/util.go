package ssh

import "os"

// fileMode converts a uint32 to os.FileMode for use with SFTP chmod.
func fileMode(m uint32) os.FileMode {
	return os.FileMode(m)
}
