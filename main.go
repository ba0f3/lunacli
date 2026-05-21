package main

import (
	"log"
	"os"

	"github.com/ba0f3/lunacli/cmd"
)

func main() {
	log.SetOutput(os.Stderr)
	cmd.Execute()
}
