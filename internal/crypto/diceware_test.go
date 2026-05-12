package crypto

import (
	"fmt"
	"strings"
	"testing"
)

func TestGenerateDicewarePassphrase_WordCount(t *testing.T) {
	for _, wordCount := range []int{1, 3, 6, 10} {
		t.Run(fmt.Sprintf("wordCount_%d", wordCount), func(t *testing.T) {
			passphrase, err := GenerateDicewarePassphrase(wordCount)
			if err != nil {
				t.Fatalf("GenerateDicewarePassphrase() error = %v", err)
			}
			words := strings.Split(passphrase, " ")
			if len(words) != wordCount {
				t.Errorf("word count = %d, want %d", len(words), wordCount)
			}
		})
	}
}

func TestGenerateDicewarePassphrase_OutputFormat(t *testing.T) {
	passphrase, err := GenerateDicewarePassphrase(6)
	if err != nil {
		t.Fatalf("GenerateDicewarePassphrase() error = %v", err)
	}

	words := strings.Split(passphrase, " ")
	if len(words) != 6 {
		t.Errorf("word count = %d, want 6", len(words))
	}

	if len(passphrase) < 30 {
		t.Errorf("passphrase length = %d, want >= 30", len(passphrase))
	}

	if passphrase != strings.TrimSpace(passphrase) {
		t.Error("expected no leading or trailing whitespace")
	}
}

func TestGenerateDicewarePassphrase_Randomness(t *testing.T) {
	p1, err := GenerateDicewarePassphrase(6)
	if err != nil {
		t.Fatalf("GenerateDicewarePassphrase() first call error = %v", err)
	}
	p2, err := GenerateDicewarePassphrase(6)
	if err != nil {
		t.Fatalf("GenerateDicewarePassphrase() second call error = %v", err)
	}
	if p1 == p2 {
		t.Error("expected different passphrases on consecutive calls")
	}
}

func TestGenerateDicewarePassphrase_InvalidCount(t *testing.T) {
	for _, wordCount := range []int{0, -1} {
		t.Run(fmt.Sprintf("wordCount_%d", wordCount), func(t *testing.T) {
			_, err := GenerateDicewarePassphrase(wordCount)
			if err == nil {
				t.Errorf("expected error for wordCount %d, got nil", wordCount)
			}
		})
	}
}

func TestGenerateDicewarePassphrase_ErrorPath(t *testing.T) {
	failingReader := &errorReader{}
	_, err := generateDicewarePassphrase(6, failingReader)
	if err == nil {
		t.Fatal("expected error from failing reader, got nil")
	}
	if !strings.Contains(err.Error(), "diceware:") {
		t.Errorf("expected error to contain 'diceware:', got %v", err)
	}
}

func TestEntropyPerWord(t *testing.T) {
	if EntropyPerWord != 12.925 {
		t.Errorf("EntropyPerWord = %v, want 12.925", EntropyPerWord)
	}
}

func TestDicewareWordlist(t *testing.T) {
	loadDicewareWordlist()
	if dicewareWordlist == nil {
		t.Fatal("dicewareWordlist is nil after loadDicewareWordlist()")
	}
	if len(dicewareWordlist) != 7776 {
		t.Errorf("dicewareWordlist length = %d, want 7776", len(dicewareWordlist))
	}
}
