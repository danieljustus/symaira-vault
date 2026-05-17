package ui

import (
	"fmt"
	"strings"

	"rsc.io/qr"
)

// MinQRWidth is the minimum terminal column count required to render a QR
// code with default settings (Level M, ~33 modules + 8-pixel quiet zone).
// Below this width the rendering would be ambiguous to scanners.
const MinQRWidth = 41

// RenderQRCode generates an ASCII QR code from the given data string using
// Level M error correction (~15% recovery), which is the sensible default
// for terminal-displayed codes that may be photographed at an angle.
// Returns a monospace-friendly string using half-block characters
// (▀ ▄ █) and spaces for scanability, or an error if encoding fails.
func RenderQRCode(data string) (string, error) {
	return RenderQRCodeWithLevel(data, qr.M)
}

// RenderQRCodeWithLevel allows callers to pick the error-correction level
// explicitly (L=7%, M=15%, Q=25%, H=30%). Higher levels make the code more
// resilient to occlusion/dirt but produce denser output.
func RenderQRCodeWithLevel(data string, level qr.Level) (string, error) {
	code, err := qr.Encode(data, level)
	if err != nil {
		return "", fmt.Errorf("qr encode: %w", err)
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

	return b.String(), nil
}

// RenderQRCodeForWidth renders a QR code only when the terminal is wide
// enough to display it scanably. If termWidth is below MinQRWidth, it
// returns ("", ErrTerminalTooNarrow) so the caller can fall back to a plain
// text token. termWidth of 0 means "skip the check" (e.g. for unit tests).
func RenderQRCodeForWidth(data string, termWidth int) (string, error) {
	if termWidth > 0 && termWidth < MinQRWidth {
		return "", ErrTerminalTooNarrow
	}
	return RenderQRCode(data)
}

// ErrTerminalTooNarrow signals that the QR code cannot be rendered in the
// available width; callers should fall back to plain token output.
var ErrTerminalTooNarrow = fmt.Errorf("terminal too narrow for QR code; need at least %d columns", MinQRWidth)

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
