package update

import (
	"context"
	"net/http"

	corekitcosign "github.com/danieljustus/symaira-corekit/updatecheck/cosign"
)

// CosignIdentityRegexp is the certificate identity regexp passed to
// cosign verify-blob. It must match the full OIDC identity embedded in
// release certificates produced by the GitHub Actions release workflow.
// The repo slug must be lowercase and hyphenated (danieljustus/symaira-vault).
// This constant is also referenced in scripts/install.sh — keep in sync.
//
// This is passed explicitly to corekitcosign.Config rather than relying on
// its IdentityRegexpOrDefault(), which double-escapes the dot separators and
// would never match a real certificate identity.
const CosignIdentityRegexp = `https://github\.com/danieljustus/symaira-vault/\.github/workflows/release\.yml@refs/tags/v.*`

// CosignOIDCIssuer is the expected OIDC issuer for cosign keyless signatures.
// All GitHub Actions workflows use this issuer. This constant is also
// referenced in scripts/install.sh — keep in sync.
const CosignOIDCIssuer = corekitcosign.OIDCIssuer

// doerRoundTripper adapts an httpDoer (vault's test-injectable interface) to
// http.RoundTripper so it can back an *http.Client, which is the concrete
// type corekitcosign.Config.HTTPClient requires.
type doerRoundTripper struct{ doer httpDoer }

func (d doerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return d.doer.Do(req)
}

// cosignHTTPClient adapts checksumsClient() (test-injectable, TLS-1.3-pinned
// by default) into the *http.Client shape corekitcosign.Config expects.
func cosignHTTPClient() *http.Client {
	doer := checksumsClient()
	if hc, ok := doer.(*http.Client); ok {
		return hc
	}
	return &http.Client{Transport: doerRoundTripper{doer: doer}}
}

func cosignConfig() corekitcosign.Config {
	return corekitcosign.Config{
		Repo:            "danieljustus/symaira-vault",
		BinaryName:      binaryName,
		DownloadBaseURL: DefaultDownloadBaseURL,
		IdentityRegexp:  CosignIdentityRegexp,
		HTTPClient:      cosignHTTPClient(),
	}
}

// FetchCosignSignature downloads the cosign signature file for the release
// checksums. The signature is produced by GoReleaser using cosign keyless
// signing and is published alongside the checksums file.
func FetchCosignSignature(ctx context.Context, version string) ([]byte, error) {
	return cosignConfig().FetchSignature(ctx, version)
}

// FetchCosignCertificate downloads the cosign certificate file for the release
// checksums. The certificate is produced by GoReleaser using cosign keyless
// signing and contains the OIDC identity from the GitHub Actions workflow run.
func FetchCosignCertificate(ctx context.Context, version string) ([]byte, error) {
	return cosignConfig().FetchCertificate(ctx, version)
}

// VerifyCosignSignature verifies a cosign keyless signature on the given content
// using the provided signature and certificate. It shells out to the cosign CLI.
//
// The verification enforces:
//   - The certificate's OIDC issuer must be GitHub Actions
//     (https://token.actions.githubusercontent.com)
//   - The certificate identity must match the Symaira Vault release workflow
//     (https://github.com/danieljustus/symaira-vault/.github/workflows/release.yml)
//     with a semantic version tag reference
//
// If the cosign CLI is not installed, the function returns a clear error
// instructing the user to install it. This is a security requirement — the
// update is aborted when cosign is not available.
func VerifyCosignSignature(content, signature, certificate []byte) error {
	return cosignConfig().VerifySignature(content, signature, certificate)
}
