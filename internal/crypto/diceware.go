package crypto

import (
	"crypto/rand"
	_ "embed"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
)

//go:embed eff_large_wordlist.txt
var dicewareWordlistData string

var (
	dicewareWordlistOnce sync.Once
	dicewareWordlist     []string
)

// EntropyPerWord is log₂(7776) ≈ 12.925 bits per word from the EFF long wordlist.
const EntropyPerWord = 12.925

func loadDicewareWordlist() {
	dicewareWordlistOnce.Do(func() {
		lines := strings.Split(strings.TrimSpace(dicewareWordlistData), "\n")
		dicewareWordlist = make([]string, 0, len(lines))
		for _, line := range lines {
			// Format: "11111\tabacus" — extract word after tab
			if _, word, ok := strings.Cut(line, "\t"); ok {
				dicewareWordlist = append(dicewareWordlist, word)
			}
		}
	})
}

// GenerateDicewarePassphrase generates a Diceware passphrase with the given
// number of words using the embedded EFF long wordlist (7776 words).
// Six words provide ≥77 bits of entropy.
//
// The wordlist is loaded lazily on first call via sync.Once.
func GenerateDicewarePassphrase(wordCount int) (string, error) {
	return generateDicewarePassphrase(wordCount, rand.Reader)
}

func generateDicewarePassphrase(wordCount int, reader io.Reader) (string, error) {
	if wordCount < 1 {
		return "", fmt.Errorf("diceware: word count must be at least 1, got %d", wordCount)
	}

	loadDicewareWordlist()
	max := big.NewInt(int64(len(dicewareWordlist)))

	words := make([]string, wordCount)
	for i := range wordCount {
		idx, err := rand.Int(reader, max)
		if err != nil {
			return "", fmt.Errorf("diceware: failed to generate random index: %w", err)
		}
		words[i] = dicewareWordlist[idx.Int64()]
	}

	return strings.Join(words, " "), nil
}
