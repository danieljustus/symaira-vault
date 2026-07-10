package payment

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDailyTotals_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daily-totals.json")
	dt, err := LoadDailyTotals(path)
	if err != nil {
		t.Fatalf("LoadDailyTotals() error = %v", err)
	}
	if dt == nil {
		t.Fatal("LoadDailyTotals() returned nil")
	}
	if got := dt.TodayTotal("policy-a"); got != "0" {
		t.Errorf("TodayTotal() = %q, want \"0\"", got)
	}
}

func TestLoadDailyTotals_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daily-totals.json")
	today := time.Now().UTC().Format("2006-01-02")
	file := dailyTotalsFile{
		Entries: map[string]map[string]string{
			"policy-a": {today: "50.00"},
		},
	}
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	dt, err := LoadDailyTotals(path)
	if err != nil {
		t.Fatalf("LoadDailyTotals() error = %v", err)
	}
	if got := dt.TodayTotal("policy-a"); got != "50.00" {
		t.Errorf("TodayTotal() = %q, want \"50.00\"", got)
	}
}

func TestAddToToday(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daily-totals.json")
	dt, err := LoadDailyTotals(path)
	if err != nil {
		t.Fatalf("LoadDailyTotals() error = %v", err)
	}

	if err := dt.AddToToday("policy-a", "25.50"); err != nil {
		t.Fatalf("AddToToday() error = %v", err)
	}
	if got := dt.TodayTotal("policy-a"); got != "51/2" {
		t.Errorf("TodayTotal() after first add = %q, want \"51/2\"", got)
	}

	if err := dt.AddToToday("policy-a", "10.25"); err != nil {
		t.Fatalf("AddToToday() error = %v", err)
	}
	if got := dt.TodayTotal("policy-a"); got != "143/4" {
		t.Errorf("TodayTotal() after second add = %q, want \"143/4\"", got)
	}
}

func TestAddToToday_PersistsToDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daily-totals.json")
	dt, err := LoadDailyTotals(path)
	if err != nil {
		t.Fatalf("LoadDailyTotals() error = %v", err)
	}
	if err := dt.AddToToday("policy-a", "30.00"); err != nil {
		t.Fatalf("AddToToday() error = %v", err)
	}

	dt2, err := LoadDailyTotals(path)
	if err != nil {
		t.Fatalf("LoadDailyTotals() error = %v", err)
	}
	if got := dt2.TodayTotal("policy-a"); got != "30" {
		t.Errorf("TodayTotal() after reload = %q, want \"30\"", got)
	}
}

func TestExpireOldEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daily-totals.json")
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	file := dailyTotalsFile{
		Entries: map[string]map[string]string{
			"policy-a": {yesterday: "100.00"},
		},
	}
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	dt, err := LoadDailyTotals(path)
	if err != nil {
		t.Fatalf("LoadDailyTotals() error = %v", err)
	}

	if got := dt.TodayTotal("policy-a"); got != "0" {
		t.Errorf("TodayTotal() = %q, want \"0\" (yesterday expired)", got)
	}
}

func TestCreateDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dir", "daily-totals.json")
	dt, err := LoadDailyTotals(path)
	if err != nil {
		t.Fatalf("LoadDailyTotals() error = %v", err)
	}
	if err := dt.AddToToday("policy-a", "10.00"); err != nil {
		t.Fatalf("AddToToday() error = %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); os.IsNotExist(err) {
		t.Error("expected directory to be created")
	}
}
