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
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

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
	fmt.Fprintf(os.Stderr, "wrote %s\n", out)
}
