package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	defaultDatadir := filepath.Join(home, ".blockbrew")

	datadir := flag.String("datadir", defaultDatadir, "data directory for blockchain and wallet")
	flag.Parse()

	fmt.Println("blockbrew v0.1.0 starting...")
	fmt.Println("datadir:", *datadir)
}
