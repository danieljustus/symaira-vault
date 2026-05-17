package a

import (
	"fmt"
	"os"

	"taint"
)

var sink string

// F contains both flagged and non-flagged uses of taint.Untrusted.
func F() {
	u := taint.Wrap("secret", taint.Provenance{Source: "test"})

	// Flagged: Untrusted directly in fmt.Sprintf
	_ = fmt.Sprintf("%s", u) // want "use of taint.Untrusted"
	_ = fmt.Sprintf("%v", u) // want "use of taint.Untrusted"
	_ = fmt.Sprintf("%d", u) // want "use of taint.Untrusted"

	// Flagged: Untrusted in other fmt print functions
	fmt.Print(u)                    // want "use of taint.Untrusted"
	fmt.Printf("%s", u)             // want "use of taint.Untrusted"
	fmt.Println(u)                  // want "use of taint.Untrusted"
	_ = fmt.Sprint(u)               // want "use of taint.Untrusted"
	_ = fmt.Sprintln(u)             // want "use of taint.Untrusted"
	fmt.Fprint(os.Stdout, u)        // want "use of taint.Untrusted"
	fmt.Fprintf(os.Stdout, "%s", u) // want "use of taint.Untrusted"
	fmt.Fprintln(os.Stdout, u)      // want "use of taint.Untrusted"

	// NOT flagged: safe extraction methods
	_ = u.Render(taint.Terminal)
	_ = u.UnsafeRawForStorage()
	_ = u.Bytes()
	_ = u.Provenance()
	_ = u.Tags()

	// NOT flagged: Untrusted.Format() itself (handled by method exclusion)
	_ = u
	sink = fmt.Sprintf("%s", u.Render(taint.Terminal))
	_ = sink

	// NOT flagged: Untrusted returned from a function called in fmt arg
	// (the return type is not Untrusted)
	_ = fmt.Sprintf("%s", safeWrap(u))
}

// safeWrap takes an Untrusted and returns a string — not flagged at the call site.
func safeWrap(u taint.Untrusted) string {
	return u.Render(taint.Terminal)
}
