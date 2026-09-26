package main

import (
	"path/filepath"
	"testing"
)

func TestGoMobileNumberFormattingAtNotationBoundaries(t *testing.T) {
	t.Chdir(filepath.Join("..", "..", "..", ".."))
	value, err := buildFixture()
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"fixed_negative_six":0.000001,"fixed_positive_twenty":100000000000000000000,"integral_one":1,"negative_zero":-0,"scientific_negative_seven":1e-7,"scientific_positive_twenty_one":1e+21}`
	if value.ExpectedJSON != want {
		t.Fatalf("Go mobile number output changed: %s", value.ExpectedJSON)
	}
	if len(value.SourceSHA256) != 2 {
		t.Fatalf("expected hashes for both Go mobile sources, got %d", len(value.SourceSHA256))
	}
}
