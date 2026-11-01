package main

import (
	"fmt"
	"math/rand"
	"strings"
)

// fuzzCases builds a deterministic pseudo-random set of templates from a
// vocabulary of template tokens. It is used with --fuzz/--seed to widen the
// differential beyond the committed corpus; its output is never committed.
func fuzzCases(seed int64, n int) []tcase {
	r := rand.New(rand.NewSource(seed)) //nolint:gosec // deterministic test data
	atoms := []string{
		".", ".Name", ".Values", ".Refs", ".Values.A", ".Values.DB_HOST", ".Refs.A", ".Missing", ".Name.x", "$", "$x", "$k", "$v", "$.Name",
		"1", "0", "-1", "2.5", "1e3", "0x10", "'a'", "1i", "\"s\"", "\"\"", "\"a b\"", "`raw`", "\"%d\"", "\"<&>\"", "nil", "true", "false",
		"printf", "print", "println", "upper", "lower", "index", "len", "eq", "ne", "lt", "le", "gt", "ge", "and", "or", "not", "slice", "html", "js", "urlquery",
		"b64enc", "b64url", "tojson", "call", "unknownfn",
	}
	words := []string{"if", "else", "end", "range", "with", "define \"d\"", "template \"d\"", "template \"d\" .", "block \"b\" .", "break", "continue", "else if", "else with"}
	puncts := []string{"|", "(", ")", ":=", "=", ",", "$x :=", "$k, $v :=", "$x =", "-", "+", ".", ":"}
	texts := []string{"", " ", "\n", "txt", "a\nb", "é", "%d", "{", "}"}
	pick := func(list []string) string { return list[r.Intn(len(list))] }
	datas := []dataset{dApp, dMasked, dSpecial, dEmpty, dOrder, dMissing}

	var out []tcase
	for i := 0; i < n; i++ {
		var sb strings.Builder
		parts := 1 + r.Intn(5)
		for p := 0; p < parts; p++ {
			sb.WriteString(pick(texts))
			sb.WriteString("{{")
			if r.Intn(8) == 0 {
				sb.WriteString("-")
			}
			sb.WriteString(" ")
			switch r.Intn(6) {
			case 0:
				sb.WriteString(pick(words))
				sb.WriteString(" ")
				if r.Intn(2) == 0 {
					sb.WriteString(pick(atoms))
				}
			default:
				k := 1 + r.Intn(5)
				for t := 0; t < k; t++ {
					switch r.Intn(7) {
					case 0:
						sb.WriteString(pick(puncts))
					default:
						sb.WriteString(pick(atoms))
					}
					sb.WriteString(" ")
				}
			}
			if r.Intn(8) == 0 {
				sb.WriteString("-")
			}
			if r.Intn(40) != 0 {
				sb.WriteString("}}")
			}
		}
		sb.WriteString(pick(texts))
		out = append(out, tcase{id: fmt.Sprintf("fuzz-%d-%05d", seed, i), group: "fuzz", src: sb.String(), data: datas[r.Intn(len(datas))]})
	}
	// Structured, mostly valid templates.
	baseExprs := []string{".Name", ".Values.DB_HOST", ".Values.A", "printf \"%v\" .", "printf \"%+v|%T\" .Values 1.5", "index .Values \"A\"", "index .Values \"zz\"", "len .Values", "len .Name", "upper .Name", "lower .Values.B", "eq .Name \"app\"", "ne .Name \"\"", "lt (len .Name) 3",
		"1", "2.5", "\"s\"", "'x'", ".", "not .", "not .Name", "tojson .Values", "tojson .Name", "slice .Name 1", "slice .Name 0 2", "and .Name .Values", "or .Missing \"d\"", "html .Values.B", "js .Values.B", "urlquery .Values.C", "b64enc .Name", "b64url .Name",
		"printf \"%s-%d\" .Name 3", "printf \"%q\" .Values", "printf \"%x\" .Name", "printf \"%08.3f\" 3.14159", "printf \"%v\" nil", "print .Name 1 2", "println .Name", "index .Name 1", "index .Name 99", "len 5", "upper 1", ".Name.x", ".Missing.y", "call .Name"}
	rangeExprs := []string{"$k", "$v", "$k | upper", "printf \"%s=%q\" $k $v", "eq $k \"A\"", "len $v", "$v | b64enc", "index $.Values $k", "tojson $v", "$k.x", "$v 1"}
	var gen func(depth int, inRange bool) string
	gen = func(depth int, inRange bool) string {
		exprs := baseExprs
		if inRange {
			exprs = append(append([]string{}, baseExprs...), rangeExprs...)
		}
		var sb strings.Builder
		for j := 0; j < 1+r.Intn(3); j++ {
			sb.WriteString(pick(texts))
			if depth > 2 || r.Intn(3) == 0 {
				sb.WriteString("{{" + pick(exprs) + "}}")
				continue
			}
			switch r.Intn(9) {
			case 0:
				sb.WriteString("{{if " + pick(exprs) + "}}" + gen(depth+1, inRange) + "{{else}}" + gen(depth+1, inRange) + "{{end}}")
			case 1:
				sb.WriteString("{{with " + pick(exprs) + "}}" + gen(depth+1, inRange) + "{{end}}")
			case 2:
				sb.WriteString("{{range $k, $v := .Values}}" + gen(depth+1, true) + "{{end}}")
			case 3:
				sb.WriteString("{{range " + pick(exprs) + "}}" + gen(depth+1, inRange) + "{{else}}" + gen(depth+1, inRange) + "{{end}}")
			case 4:
				sb.WriteString("{{$x := " + pick(exprs) + "}}{{$x}}" + gen(depth+1, inRange))
			case 5:
				sb.WriteString("{{define \"d\"}}" + gen(depth+1, false) + "{{end}}{{template \"d\" " + pick(exprs) + "}}")
			case 6:
				sb.WriteString("{{range $i, $e := " + pick([]string{"3", "0", ".Refs", ".Values", "(len .Name)"}) + "}}" + gen(depth+1, true) + "{{if eq $i 1}}{{break}}{{end}}{{end}}")
			case 7:
				sb.WriteString("{{block \"blk\" " + pick(exprs) + "}}" + gen(depth+1, false) + "{{end}}")
			default:
				sb.WriteString("{{range $k, $v := .Refs}}{{if " + pick(exprs) + "}}{{break}}{{else}}{{continue}}{{end}}{{end}}")
			}
		}
		return sb.String()
	}
	for i := 0; i < n; i++ {
		out = append(out, tcase{id: fmt.Sprintf("fuzzs-%d-%05d", seed, i), group: "fuzz", src: gen(0, false), data: datas[r.Intn(len(datas))]})
	}
	return out
}
