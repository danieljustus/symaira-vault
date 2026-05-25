//go:build !metrics

package serverbootstrap

import (
	"fmt"
	"net/http"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// registerMetricsEndpoint registers a stub /metrics endpoint that returns
// 501 Not Implemented when metrics support is not compiled in.
func registerMetricsEndpoint(mux *http.ServeMux, _ *vaultpkg.Vault, _ string, _ string, _ any, _ any) {
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = fmt.Fprintln(w, "metrics not compiled in (build with -tags metrics)")
	})
}
