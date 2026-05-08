package vault

import (
	"fmt"
	"testing"
	"encoding/json"

	"filippo.io/age"
)

func TestDebugMetadata(t *testing.T) {
	dir := t.TempDir()
	identity, _ := age.GenerateX25519Identity()

	entry := &Entry{
		Data: map[string]any{
			"password": "testpass123",
			"username": "testuser",
		},
	}
	WriteEntry(dir, "github", entry, identity)

	readBack, err := ReadEntry(dir, "github", identity)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("ReadBack Metadata: %+v\n", readBack.Metadata)

	b, _ := json.Marshal(readBack)
	fmt.Println("Entry JSON:", string(b))
}
