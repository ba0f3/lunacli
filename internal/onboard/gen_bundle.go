//go:build ignore

package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	const srcDir = "bundle_src"
	const out = "bundle.tar.gz"

	f, err := os.Create(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create %s: %v\n", out, err)
		os.Exit(1)
	}

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	entries := []string{"policy.yml", "hosts.yml"}
	for _, name := range entries {
		path := filepath.Join(srcDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
			os.Exit(1)
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(data)),
		}); err != nil {
			fmt.Fprintf(os.Stderr, "header %s: %v\n", name, err)
			os.Exit(1)
		}
		if _, err := tw.Write(data); err != nil {
			fmt.Fprintf(os.Stderr, "body %s: %v\n", name, err)
			os.Exit(1)
		}
	}

	if err := tw.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close tar writer: %v\n", err)
		os.Exit(1)
	}
	if err := gw.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close gzip writer: %v\n", err)
		os.Exit(1)
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close file: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "wrote %s\n", out)
}
