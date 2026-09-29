package main

import (
	"fmt"
	"os"
)

func main() {
	_, _ = fmt.Fprint(os.Stdout, os.Getenv("GITHUB_PASSWORD"))
}
