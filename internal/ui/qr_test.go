package ui

import (
	"errors"
	"strings"
	"testing"
)

func TestRenderQRCode_Success(t *testing.T) {
	out, err := RenderQRCode("hello world")
	if err != nil {
		t.Fatalf("RenderQRCode() err = %v", err)
	}
	if !strings.Contains(out, "█") && !strings.Contains(out, "▀") && !strings.Contains(out, "▄") {
		t.Errorf("output contains no block characters; got %q", out)
	}
}

func TestRenderQRCodeForWidth_TooNarrow(t *testing.T) {
	_, err := RenderQRCodeForWidth("hello", 20)
	if !errors.Is(err, ErrTerminalTooNarrow) {
		t.Errorf("err = %v, want ErrTerminalTooNarrow", err)
	}
}

func TestRenderQRCodeForWidth_Wide(t *testing.T) {
	out, err := RenderQRCodeForWidth("hello", 120)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out == "" {
		t.Error("expected non-empty QR output")
	}
}

func TestRenderQRCodeForWidth_ZeroBypassesCheck(t *testing.T) {
	out, err := RenderQRCodeForWidth("hello", 0)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out == "" {
		t.Error("expected non-empty QR output")
	}
}
