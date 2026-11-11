package main

import (
	"os"

	"github.com/Trysac/u257-k8s-manifest-security"
)

func main() {
	os.Exit(k8smanifestsecurity.Run(os.Args[1:], os.Stdout, os.Stderr))
}
