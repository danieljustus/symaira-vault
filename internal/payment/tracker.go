package payment

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type DailyTotals struct {
	mu      sync.Mutex
	entries map[string]map[string]string
	path    string
}

type dailyTotalsFile struct {
	Entries map[string]map[string]string `json:"entries"`
}

func LoadDailyTotals(path string) (*DailyTotals, error) {
	dt := &DailyTotals{
		entries: make(map[string]map[string]string),
		path:    path,
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return dt, nil
		}
		return nil, fmt.Errorf("read daily totals: %w", err)
	}
	var file dailyTotalsFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse daily totals: %w", err)
	}
	if file.Entries != nil {
		dt.entries = file.Entries
	}
	dt.expireOldEntries()
	return dt, nil
}

func (dt *DailyTotals) expireOldEntries() {
	today := time.Now().UTC().Format("2006-01-02")
	for policy, dates := range dt.entries {
		for dateKey := range dates {
			if dateKey < today {
				delete(dates, dateKey)
			}
		}
		if len(dates) == 0 {
			delete(dt.entries, policy)
		}
	}
}

func (dt *DailyTotals) TodayTotal(policyName string) string {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	today := time.Now().UTC().Format("2006-01-02")
	if dates, ok := dt.entries[policyName]; ok {
		if total, ok := dates[today]; ok {
			return total
		}
	}
	return "0"
}

func (dt *DailyTotals) AddToToday(policyName, amount string) error {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	today := time.Now().UTC().Format("2006-01-02")
	if dt.entries[policyName] == nil {
		dt.entries[policyName] = make(map[string]string)
	}
	current := dt.entries[policyName][today]
	if current == "" {
		current = "0"
	}
	sum, err := addRatStrings(current, amount)
	if err != nil {
		return fmt.Errorf("add amounts: %w", err)
	}
	dt.entries[policyName][today] = sum
	return dt.save()
}

func (dt *DailyTotals) save() error {
	dt.expireOldEntries()
	file := dailyTotalsFile{Entries: dt.entries}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal daily totals: %w", err)
	}
	dir := filepath.Dir(dt.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create payment state dir: %w", err)
	}
	if err := os.WriteFile(dt.path, data, 0o600); err != nil {
		return fmt.Errorf("write daily totals: %w", err)
	}
	return nil
}

func addRatStrings(a, b string) (string, error) {
	ra, ok := new(big.Rat).SetString(a)
	if !ok {
		return "", fmt.Errorf("parse %q as decimal", a)
	}
	rb, ok := new(big.Rat).SetString(b)
	if !ok {
		return "", fmt.Errorf("parse %q as decimal", b)
	}
	sum := new(big.Rat).Add(ra, rb)
	return sum.RatString(), nil
}
