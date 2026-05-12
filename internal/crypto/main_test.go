package crypto

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	restore := SetTestScryptWorkFactor(12)
	code := m.Run()
	restore()
	os.Exit(code)
}
