package ui

import (
	"strings"

	"rsc.io/qr"
)

// RenderQRCode generates an ASCII QR code from the given data string.
// Returns a monospace-friendly string suitable for terminal rendering.
// The output uses half-block characters (▀ ▄ █) and spaces for scanability.
func RenderQRCode(data string) string {
	code, err := qr.Encode(data, qr.L)
	if err != nil {
		return "Error: " + err.Error()
	}

	size := code.Size
	// Add quiet zone (4 pixels white border on each side)
	totalSize := size + 8

	var b strings.Builder

	for y := 0; y < totalSize; y += 2 {
		for x := 0; x < totalSize; x++ {
			top := isBlack(x, y, size, code)
			bottom := isBlack(x, y+1, size, code)

			switch {
			case top && bottom:
				b.WriteString("█")
			case top && !bottom:
				b.WriteString("▀")
			case !top && bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}

// isBlack returns true if the pixel at (x, y) in the QR code's total
// coordinate space (including quiet zone) is black.
func isBlack(x, y, size int, code *qr.Code) bool {
	// Quiet zone: 4 pixels of white border
	ix := x - 4
	iy := y - 4

	if ix < 0 || iy < 0 || ix >= size || iy >= size {
		return false // white border
	}
	return code.Black(ix, iy)
}
