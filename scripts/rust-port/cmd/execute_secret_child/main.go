package main

import (
	"fmt"
	"os"
)

func main() {
	_, _ = fmt.Fprintf(os.Stdout, "%s:%s", os.Getenv("GITHUB_PASSWORD"), os.Getenv("PLAIN"))
}
