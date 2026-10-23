//go:build !linux

package main

import "errors"

func runAutotypeCase(c autotypeCase) (autotypeCase, error) {
	return c, errors.New("autotype scenarios require GOOS=linux")
}
