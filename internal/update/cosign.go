package update

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// execCommand is overridden in tests to allow verification without the cosign
// CLI being installed.
var execCommand = exec.Command

// cosignSignatureFileName returns the cosign signature filename for the
// checksums file of the given release version. Matches the GoReleaser
// cosign signing convention where "<artifact>.sig" is the signature.
func cosignSignatureFileName(version string) string {
	v := strings.TrimPrefix(version, "v")
	return fmt.Sprintf("OpenPass_%s_checksums.txt.sig", v)
}

// cosignCertificateFileName returns the cosign certificate filename for the
// checksums file of the given release version. Matches the GoReleaser
// cosign signing convention where "<artifact>.pem" is the certificate.
func cosignCertificateFileName(version string) string {
	v := strings.TrimPrefix(version, "v")
	return fmt.Sprintf("OpenPass_%s_checksums.txt.pem", v)
}

// fetchCosignArtifact downloads a cosign artifact (signature or certificate)
// for the given release version. The artifactName function produces the
// filename (e.g., cosignSignatureFileName or cosignCertificateFileName).
func fetchCosignArtifact(ctx context.Context, version string, artifactName func(string) string, artifactLabel string) ([]byte, error) {
	v := strings.TrimPrefix(version, "v")
	if v == "" {
		return nil, fmt.Errorf("version must not be empty")
	}

	name := artifactName(version)
	u := fmt.Sprintf("%s/v%s/%s", DefaultDownloadBaseURL, v, name)

	parsed, err := url.Parse(u)
	if err != nil {
		return nil, fmt.Errorf("invalid cosign %s URL: %w", artifactLabel, err)
	}
	const httpsScheme = "https"
	if parsed.Scheme != httpsScheme {
		return nil, fmt.Errorf("cosign %s URL must use HTTPS, got %q", artifactLabel, parsed.Scheme)
	}

	client := checksumsClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("create cosign %s request: %w", artifactLabel, err)
	}

	resp, err := client.Do(req) // #nosec G107 — URL is constructed from controlled inputs
	if err != nil {
		return nil, fmt.Errorf("fetch cosign %s: %w", artifactLabel, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch cosign %s: HTTP %d", artifactLabel, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read cosign %s response: %w", artifactLabel, err)
	}

	return data, nil
}

// FetchCosignSignature downloads the cosign signature file for the release
// checksums. The signature is produced by GoReleaser using cosign keyless
// signing and is published alongside the checksums file.
func FetchCosignSignature(ctx context.Context, version string) ([]byte, error) {
	return fetchCosignArtifact(ctx, version, cosignSignatureFileName, "signature")
}

// FetchCosignCertificate downloads the cosign certificate file for the release
// checksums. The certificate is produced by GoReleaser using cosign keyless
// signing and contains the OIDC identity from the GitHub Actions workflow run.
func FetchCosignCertificate(ctx context.Context, version string) ([]byte, error) {
	return fetchCosignArtifact(ctx, version, cosignCertificateFileName, "certificate")
}

// VerifyCosignSignature verifies a cosign keyless signature on the given content
// using the provided signature and certificate. It shells out to the cosign CLI.
//
// The verification enforces:
//   - The certificate's OIDC issuer must be GitHub Actions
//     (https://token.actions.githubusercontent.com)
//   - The certificate identity must match the OpenPass release workflow
//     (https://github.com/danieljustus/OpenPass/.github/workflows/release.yml)
//     with a semantic version tag reference
//
// If the cosign CLI is not installed, the function returns a clear error
// instructing the user to install it. This is a security requirement — the
// update is aborted when cosign is not available.
func VerifyCosignSignature(content, signature, certificate []byte) error {
	if _, err := exec.LookPath("cosign"); err != nil {
		return fmt.Errorf(
			"cosign CLI not found — install cosign from https://docs.sigstore.dev "+
				"to verify release signatures: %w", err,
		)
	}

	tmpDir, err := os.MkdirTemp("", "openpass-cosign-*")
	if err != nil {
		return fmt.Errorf("create temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	contentPath := filepath.Join(tmpDir, "content")
	sigPath := filepath.Join(tmpDir, "signature.sig")
	certPath := filepath.Join(tmpDir, "certificate.pem")

	if err := os.WriteFile(contentPath, content, 0o600); err != nil {
		return fmt.Errorf("write content file: %w", err)
	}
	if err := os.WriteFile(sigPath, signature, 0o600); err != nil {
		return fmt.Errorf("write signature file: %w", err)
	}
	if err := os.WriteFile(certPath, certificate, 0o600); err != nil {
		return fmt.Errorf("write certificate file: %w", err)
	}

	var stderr bytes.Buffer
	cmd := execCommand("cosign",
		"verify-blob",
		"--certificate", certPath,
		"--signature", sigPath,
		"--certificate-identity-regexp",
		`https://github\.com/danieljustus/OpenPass/\.github/workflows/release\.yml@refs/tags/v.*`,
		"--certificate-oidc-issuer",
		"https://token.actions.githubusercontent.com",
		contentPath,
	)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf(
			"cosign verify-blob failed: %s: %w",
			strings.TrimSpace(stderr.String()),
			err,
		)
	}

	return nil
}
