package onboard

import (
	"fmt"
	"io"
)

func writef(w io.Writer, format string, args ...any) error {
	_, err := fmt.Fprintf(w, format, args...)
	return err
}

func writeln(w io.Writer, s string) error {
	_, err := fmt.Fprintln(w, s)
	return err
}

func writeBlank(w io.Writer) error {
	_, err := fmt.Fprintln(w)
	return err
}
