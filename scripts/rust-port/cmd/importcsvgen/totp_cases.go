package main

import "strings"

// mutatedTOTPInputs returns deterministic base32 mutations of a valid secret.
// Every input is fed to the production importer.ParseTOTP by main, so the
// expected value or error text always comes from Go, never from this file.
func mutatedTOTPInputs(secret string) []string {
	var inputs []string
	add := func(values ...string) { inputs = append(inputs, values...) }

	// Issue #1467: Go accepts a 38-character unpadded secret (a final group
	// of six characters contributes no bytes) and rejects the 26-character one
	// as too short rather than as non-Base32.
	add("JBSWY3DPEHPK3PXPJBSPXPJBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PWY3DPEHPK3PXP")

	// Every prefix length around and past the 26-character minimum, with and
	// without padding to the next multiple of eight.
	for n := 1; n <= len(secret); n++ {
		prefix := secret[:n]
		add(prefix)
		if pad := (8 - n%8) % 8; pad > 0 {
			add(prefix + strings.Repeat("=", pad))
		}
	}
	// Missing, short, extra and misplaced padding on a valid 32-character body.
	for k := 1; k <= 9; k++ {
		add(secret + strings.Repeat("=", k))
	}
	for _, n := range []int{24, 26, 28, 29, 30, 31} {
		prefix := secret[:n]
		for k := 0; k <= 8; k++ {
			add(prefix + strings.Repeat("=", k))
		}
	}
	add(secret[:26]+"======ZZ", secret[:26]+"=======XYZ", secret[:26]+"=A====", secret[:26]+"==A===",
		secret[:25]+"===", secret[:27]+"=", "="+secret, secret[:10]+"="+secret[10:], "====", "========",
		secret[:24]+"AB======ZZ", secret[:24]+"A=======", secret[:24]+"ABC=====")
	// Case folding and spaces. Only the ASCII space is stripped.
	add(strings.ToLower(secret), strings.ToLower(secret[:26]), strings.ToLower(secret[:26])+"======",
		strings.ToLower(secret[:10])+secret[10:], "JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP",
		"jbsw y3dp ehpk 3pxp jbsw y3dp ehpk 3pxp", " "+secret[:26]+" ", secret[:13]+"  "+secret[13:],
		secret[:26]+"== ====", "J B S W Y 3 D P E H P K 3 P X P J B S W Y 3 D P E H P K 3 P X P",
		"\t"+secret, secret[:16]+"\t"+secret[16:], secret[:16]+"\u00a0"+secret[16:])
	// CR and LF are ignored by encoding/base32, but a leading/trailing
	// whitespace run is trimmed first by ParseTOTP.
	add(secret[:16]+"\n"+secret[16:], secret[:16]+"\r\n"+secret[16:], secret+"\n", "\n"+secret,
		secret[:26]+"\n======", secret[:26]+"=\r\n=====", secret[:26]+"\n", secret[:7]+"\r"+secret[7:26])
	// Characters outside the alphabet, including the ones whose Unicode case
	// mapping reaches ASCII (U+0131, U+017F) or expands (U+00DF).
	add(secret[:30]+"0"+secret[31:], secret[:30]+"1"+secret[31:], secret[:30]+"8"+secret[31:],
		secret[:30]+"9"+secret[31:], secret[:30]+"-"+secret[31:], secret[:30]+"_"+secret[31:],
		secret[:30]+"\x00"+secret[31:], secret[:30]+"\u00df"+secret[31:], secret[:30]+"\u0131"+secret[31:],
		secret[:30]+"\u017f"+secret[31:], secret[:30]+"\u0149"+secret[31:], secret[:30]+"\u212a"+secret[31:],
		secret[:30]+"\u00e9"+secret[31:], "\u0131"+secret[1:], secret[:26]+"\u017f\u017f\u017f\u017f\u017f\u017f",
		strings.Repeat("\u00df", 100), strings.Repeat("\u0131", 150), strings.Repeat("\u017f", 128)+secret)
	// Length limit (counted in bytes after upper-casing) and odd lengths of
	// long unpadded secrets.
	add(strings.Repeat("JBSWY3DP", 32), strings.Repeat("JBSWY3DP", 32)+"A", strings.Repeat("jbswy3dp", 32),
		strings.Repeat("JBSWY3DP", 31)+"JBSWY3D", strings.Repeat("JBSWY3DP", 31)+"JBSWY3DPE",
		strings.Repeat("JBSWY3DP", 31)+"JBSWY3==", strings.Repeat("JBSWY3DP", 33),
		strings.Repeat("JBSWY3DP", 3)+"JBSWY3DPEHPK", strings.Repeat("JBSWY3DP", 3)+"JBS",
		strings.Repeat("JBSWY3DP", 3)+"JB", strings.Repeat("JBSWY3DP", 3)+"J",
		strings.Repeat("JBSWY3DP", 3)+"JBSWY3", strings.Repeat("JBSWY3DP", 3)+"JBSWY3D")
	// Weak or degenerate payloads reached through the different decode paths.
	add(strings.Repeat("A", 26), strings.Repeat("A", 32), strings.Repeat("A", 38), strings.Repeat("A", 40),
		strings.Repeat("A", 25)+"=======", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
		strings.Repeat("7", 32), strings.Repeat("AB", 16), "AAAAAAAAAAAAAAAAAAAAAAAAAA======")

	// otpauth URIs carry the same secret through URL query decoding.
	uri := func(raw string) string { return "otpauth://totp/x?secret=" + raw }
	add(uri(secret[:26]), uri(secret[:25]), uri("JBSWY3DPEHPK3PXPJBSPXPJBSWY3DPEHPK3PXP"),
		uri("JBSWY3DPEHPK3PWY3DPEHPK3PXP"), uri(strings.ToLower(secret)), uri(secret+"%3D"),
		uri(secret[:26]+"%3D%3D%3D%3D%3D%3D"), uri(secret[:26]+"======"), uri(secret[:26]+"%3d%3d"),
		uri(secret[:16]+"%20"+secret[16:]), uri(secret[:16]+"+"+secret[16:]), uri(secret[:16]+"%0A"+secret[16:]),
		uri(secret[:16]+"%0d%0a"+secret[16:]), uri("%20"+secret), uri(secret[:30]+"%C3%9F"+secret[31:]),
		uri(secret[:30]+"%C4%B1"+secret[31:]), uri(secret[:30]+"%C5%BF"+secret[31:]), uri(secret[:30]+"%01"+secret[31:]),
		uri(secret[:30]+"0"+secret[31:]), uri(strings.Repeat("JBSWY3DP", 33)), uri(strings.Repeat("JBSWY3DP", 32)),
		uri("AAAAAAAAAAAAAAAAAAAAAAAAAA"), uri("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), uri("%41%42%43"),
		uri(secret)+"&secret=bad", uri("bad")+"&secret="+secret, "otpauth://totp/x?secret="+secret[:26]+"&digits=8",
		"otpauth://totp/x?issuer=a&secret="+secret[:25]+"&period=60", "  OTPAUTH://totp/x?secret="+strings.ToLower(secret[:26])+"  ")
	return inputs
}
