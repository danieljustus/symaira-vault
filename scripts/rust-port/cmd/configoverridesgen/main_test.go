package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--probe" {
		var item vector
		if err := json.NewDecoder(os.Stdin).Decode(&item); err != nil {
			panic(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(probe(item)); err != nil {
			panic(err)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestOracleRepeatability(t *testing.T) {
	cases := inputs()
	if len(cases) != 59 {
		t.Fatalf("case count %d", len(cases))
	}
	seen := map[string]bool{}
	classes := map[string]int{}
	for _, item := range cases {
		if seen[item.Name] {
			t.Fatalf("duplicate case %s", item.Name)
		}
		seen[item.Name] = true
		first, err := capture(item)
		if err != nil {
			t.Fatal(err)
		}
		second, err := capture(item)
		if err != nil {
			t.Fatal(err)
		}
		if first != second {
			t.Fatalf("nondeterministic %s: %+v != %+v", item.Name, first, second)
		}
		classes[first.ErrorClass]++
	}
	if classes["flags"] == 0 || classes["profile"] == 0 || classes["config"] == 0 || classes[""] == 0 {
		t.Fatalf("missing result class: %+v", classes)
	}
	t.Logf("executed %d cases twice; result classes: %+v", len(cases), classes)
}

func TestReservedEnvironmentFailsClosed(t *testing.T) {
	_, err := capture(vector{Name: "reserved", Env: map[string]string{"HOME": "outside"}})
	if err == nil {
		t.Fatal("reserved HOME override accepted")
	}
}
