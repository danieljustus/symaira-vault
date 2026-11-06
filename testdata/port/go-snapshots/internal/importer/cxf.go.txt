package importer

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/crypto"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// Credential type values are compared after normalization (lowercase,
// dashes/underscores stripped) so the spec-cased values of the FIDO
// Credential Exchange Format (CXF) Proposed Standard of 2025-08-14
// ("basic-auth", "ssh-key", ...) and draft-era CamelCase exports
// ("BasicAuth", "Cryptographic-key", ...) are both accepted.
const (
	cxfNormBasicAuth  = "basicauth"
	cxfNormTOTP       = "totp"
	cxfNormNote       = "note"
	cxfNormPasskey    = "passkey"
	cxfNormSSHKey     = "sshkey"
	cxfNormCryptoKey  = "cryptographickey" // draft-era SSH key type name
	cxfNormCreditCard = "creditcard"
	cxfNormFile       = "file"
	cxfNormAddress    = "address"
)

// CXF JSON document member names reused across the parse helpers.
const (
	cxfFieldUsername = "username"
	cxfFieldPassword = "password"
	cxfFieldURL      = "url"
	cxfFieldURLs     = "urls"
	cxfFieldNotes    = "notes"
	cxfFieldTags     = "tags"
	cxfFieldTOTP     = "totp"
	cxfFieldPasskey  = "passkey"
	cxfFieldPasskeys = "passkeys"
	cxfFieldPrivKey  = "private_key"
)

// CXF payload file names looked up preferentially inside the archive. The
// specification does not mandate an archive layout, so both common
// conventions are accepted.
const (
	cxfPayloadName    = "cxf.json"
	cxfPayloadAltName = "payload.json"
)

// cxfImporter parses a FIDO Credential Exchange Format (CXF) archive: a zip
// file containing one JSON document describing accounts, collections and
// items with typed credentials. Only plain, locally-exported archives are
// supported — the per-part encryption of CXP transfers does not apply to
// local exports.
type cxfImporter struct{}

// cxfExport is the top-level CXF JSON document (Header dictionary).
type cxfExport struct {
	Version  cxfVersion   `json:"version"`
	Accounts []cxfAccount `json:"accounts"`
}

type cxfVersion struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}

// cxfAccount represents one credential owner's account in the exporter.
type cxfAccount struct {
	ID          string          `json:"id"`
	Username    string          `json:"username"`
	Email       string          `json:"email"`
	Collections []cxfCollection `json:"collections"`
	Items       []cxfItem       `json:"items"`
}

// cxfCollection groups items; items are referenced by their base64url id
// (LinkedItem). Nested subCollections become deeper path segments.
type cxfCollection struct {
	ID             string          `json:"id"`
	Title          string          `json:"title"`
	Name           string          `json:"name"` // draft-era fallback
	Items          []cxfLinkedItem `json:"items"`
	SubCollections []cxfCollection `json:"subCollections"`
}

type cxfLinkedItem struct {
	Item    string `json:"item"`
	Account string `json:"account"`
}

// cxfItem contains the typed credentials of one entry.
type cxfItem struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Name        string            `json:"name"` // draft-era fallback
	Scope       cxfScope          `json:"scope"`
	Credentials []json.RawMessage `json:"credentials"`
	Tags        []string          `json:"tags"`
}

// cxfScope declares where the item's credentials should be presented; the
// urls apply to BasicAuth credentials.
type cxfScope struct {
	URLs []string `json:"urls"`
}

// cxfFieldValue decodes a CXF field value. The specification wraps values in
// an EditableField dictionary ({"fieldType": ..., "value": ...}); draft-era
// exports and some providers emit bare strings instead. Both are accepted.
type cxfFieldValue struct {
	Value string
}

// UnmarshalJSON accepts either a bare string or an EditableField object.
func (f *cxfFieldValue) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		f.Value = text
		return nil
	}
	var object struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(data, &object); err != nil {
		return err
	}
	f.Value = object.Value
	return nil
}

type cxfBasicAuth struct {
	Username cxfFieldValue `json:"username"`
	Password cxfFieldValue `json:"password"`
	URLs     []string      `json:"urls"` // draft-era placement
}

type cxfTOTP struct {
	Secret    string `json:"secret"`
	Period    int    `json:"period"`
	Digits    int    `json:"digits"`
	Algorithm string `json:"algorithm"`
	Issuer    string `json:"issuer"`
	Username  string `json:"username"`
}

type cxfNote struct {
	Content cxfFieldValue `json:"content"`
}

type cxfSSHKey struct {
	KeyType       string `json:"keyType"`
	PrivateKey    string `json:"privateKey"`
	PrivateKeyPem string `json:"privateKeyPem"` // draft-era field
	KeyComment    string `json:"keyComment"`
}

type cxfCreditCard struct {
	Number             cxfFieldValue `json:"number"`
	FullName           cxfFieldValue `json:"fullName"`
	CardType           cxfFieldValue `json:"cardType"`
	VerificationNumber cxfFieldValue `json:"verificationNumber"`
	ExpiryDate         cxfFieldValue `json:"expiryDate"`
}

// Parse reads a CXF zip archive and maps its items onto vault entries.
func (i *cxfImporter) Parse(r io.Reader) ([]ImportedEntry, error) {
	limited := io.LimitReader(r, maxImportSize)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read import source: %w", err)
	}
	if len(data) >= int(maxImportSize) {
		return nil, fmt.Errorf("import source exceeds maximum size of %d bytes", maxImportSize)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open cxf zip: %w", err)
	}

	payload, err := readCXFJSON(zr)
	if err != nil {
		return nil, err
	}

	var export cxfExport
	if err := json.Unmarshal(payload, &export); err != nil {
		return nil, fmt.Errorf("parse CXF JSON document: %w", err)
	}

	var entries []ImportedEntry
	for _, account := range export.Accounts {
		entries = append(entries, cxfAccountEntries(account)...)
	}
	return entries, nil
}

// readCXFJSON locates the CXF JSON document inside the zip archive. The
// specification does not mandate an archive layout, so the document is found
// defensively: a cxf.json or payload.json entry wins, otherwise the single
// (or largest) .json entry is used.
func readCXFJSON(zr *zip.Reader) ([]byte, error) {
	var candidates []*zip.File
	for _, file := range zr.File {
		if file.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(file.Name), ".json") {
			continue
		}
		candidates = append(candidates, file)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no CXF JSON document found in cxf zip")
	}

	pick := candidates[0]
	preferred := false
	for _, file := range candidates {
		base := path.Base(file.Name)
		if strings.EqualFold(base, cxfPayloadName) || strings.EqualFold(base, cxfPayloadAltName) {
			pick = file
			preferred = true
			break
		}
	}
	if !preferred && len(candidates) > 1 {
		for _, file := range candidates[1:] {
			if file.UncompressedSize64 > pick.UncompressedSize64 {
				pick = file
			}
		}
	}

	rc, err := pick.Open()
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", pick.Name, err)
	}
	defer func() { _ = rc.Close() }()

	limited := io.LimitReader(rc, int64(maxZipEntrySize))
	payload, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", pick.Name, err)
	}
	if len(payload) == maxZipEntrySize {
		return nil, fmt.Errorf("zip entry exceeds maximum size of %d bytes", maxZipEntrySize)
	}
	return payload, nil
}

// cxfAccountEntries maps every item of an account onto vault entries. Items
// linked from a collection import under "collection/title" paths (nested
// collections become deeper segments); items not linked from any collection
// import under their own title. Items whose credentials all failed to map
// are skipped so no empty vault entries are written.
func cxfAccountEntries(account cxfAccount) []ImportedEntry {
	itemsByID := make(map[string]cxfItem, len(account.Items))
	for _, item := range account.Items {
		if item.ID != "" {
			itemsByID[item.ID] = item
		}
	}

	// placed tracks items already reached through a collection so the
	// bare-item pass below does not import them a second time. An item
	// linked from several collections imports once per collection.
	placed := make(map[string]bool, len(account.Items))

	var entries []ImportedEntry
	add := func(item cxfItem, collectionPath string) {
		if collectionPath == "" && item.ID != "" && placed[item.ID] {
			return
		}
		entry, ok := cxfItemEntry(item, collectionPath)
		if !ok {
			return
		}
		if collectionPath != "" && item.ID != "" {
			placed[item.ID] = true
		}
		entries = append(entries, entry)
	}

	var walk func(collections []cxfCollection, parentPath string)
	walk = func(collections []cxfCollection, parentPath string) {
		for _, collection := range collections {
			collectionPath := ApplyPrefix(parentPath, cxfCollectionTitle(collection))
			for _, linked := range collection.Items {
				if item, ok := itemsByID[linked.Item]; ok {
					add(item, collectionPath)
				}
			}
			walk(collection.SubCollections, collectionPath)
		}
	}
	walk(account.Collections, "")

	for _, item := range account.Items {
		add(item, "")
	}
	return entries
}

// cxfItemData accumulates the vault fields, warnings and secret metadata of
// one CXF item while its credentials are applied one by one.
type cxfItemData struct {
	data     map[string]any
	warnings []string
	urls     []string
	metadata *vaultpkg.SecretMetadata
}

// cxfItemEntry maps one CXF item onto an ImportedEntry. The second return
// value reports whether the item produced any importable data.
func cxfItemEntry(item cxfItem, collectionPath string) (ImportedEntry, bool) {
	acc := &cxfItemData{data: make(map[string]any)}
	hasBasicAuth := false

	for _, raw := range item.Credentials {
		cred, ctype := cxfParseCredential(raw)
		if cred == nil || ctype == "" {
			continue
		}
		switch normalizeCXFType(ctype) {
		case cxfNormBasicAuth:
			hasBasicAuth = true
			acc.applyBasicAuth(raw)
		case cxfNormTOTP:
			acc.applyTOTP(raw)
		case cxfNormNote:
			acc.applyNote(raw)
		case cxfNormPasskey:
			acc.applyPasskey(cred)
		case cxfNormSSHKey, cxfNormCryptoKey:
			acc.applySSHKey(raw)
		case cxfNormCreditCard:
			acc.applyCreditCard(raw)
		case cxfNormFile, cxfNormAddress:
			acc.skip(ctype)
		default:
			acc.skip(ctype)
		}
	}

	if hasBasicAuth {
		urls := cxfNonEmptyURLs(item.Scope.URLs)
		if len(urls) == 0 {
			urls = cxfNonEmptyURLs(acc.urls)
		}
		if len(urls) > 0 {
			acc.data[cxfFieldURL] = urls[0]
			acc.data[cxfFieldURLs] = urls
		}
	}
	if len(item.Tags) > 0 {
		acc.data[cxfFieldTags] = item.Tags
	}

	if len(acc.data) == 0 {
		return ImportedEntry{}, false
	}

	entryPath := NormalizePath(ApplyPrefix(collectionPath, cxfItemTitle(item)))
	if entryPath == "" {
		return ImportedEntry{}, false
	}
	entry := ImportedEntry{Path: entryPath, Data: acc.data, Warnings: acc.warnings}
	if acc.metadata != nil {
		entry.SecretMetadata = acc.metadata
	}
	return entry, true
}

func (d *cxfItemData) applyBasicAuth(raw json.RawMessage) {
	var c cxfBasicAuth
	if err := json.Unmarshal(raw, &c); err != nil {
		d.warnings = append(d.warnings, fmt.Sprintf("cxf: basic-auth: %v", err))
		return
	}
	d.data[cxfFieldUsername] = c.Username.Value
	d.data[cxfFieldPassword] = c.Password.Value
	d.urls = c.URLs
}

func (d *cxfItemData) applyTOTP(raw json.RawMessage) {
	var c cxfTOTP
	if err := json.Unmarshal(raw, &c); err != nil {
		d.warnings = append(d.warnings, fmt.Sprintf("cxf: totp: %v", err))
		return
	}
	if totp, err := cxfTOTPData(c); err == nil {
		d.data[cxfFieldTOTP] = totp
	} else {
		d.warnings = append(d.warnings, fmt.Sprintf("totp: %v", err))
	}
}

func (d *cxfItemData) applyNote(raw json.RawMessage) {
	var c cxfNote
	if err := json.Unmarshal(raw, &c); err != nil {
		d.warnings = append(d.warnings, fmt.Sprintf("cxf: note: %v", err))
		return
	}
	if c.Content.Value == "" {
		return
	}
	if existing, ok := d.data[cxfFieldNotes].(string); ok && existing != "" {
		d.data[cxfFieldNotes] = existing + "\n\n" + c.Content.Value
	} else {
		d.data[cxfFieldNotes] = c.Content.Value
	}
}

// applyPasskey stores the passkey credential opaquely. The first passkey on
// an item lands in the "passkey" field; further ones are collected in
// "passkeys".
func (d *cxfItemData) applyPasskey(cred map[string]any) {
	if _, exists := d.data[cxfFieldPasskey]; !exists {
		d.data[cxfFieldPasskey] = cred
		return
	}
	if list, ok := d.data[cxfFieldPasskeys].([]any); ok {
		d.data[cxfFieldPasskeys] = append(list, cred)
		return
	}
	d.data[cxfFieldPasskeys] = []any{d.data[cxfFieldPasskey], cred}
}

func (d *cxfItemData) applySSHKey(raw json.RawMessage) {
	var c cxfSSHKey
	if err := json.Unmarshal(raw, &c); err != nil {
		d.warnings = append(d.warnings, fmt.Sprintf("cxf: ssh-key: %v", err))
		return
	}
	key := c.PrivateKey
	if key == "" {
		key = c.PrivateKeyPem
	}
	if key == "" {
		return
	}
	d.data[cxfFieldPrivKey] = cxfSSHKeyMaterial(key)
	d.metadata = &vaultpkg.SecretMetadata{
		Type:      vaultpkg.SecretTypeSSHKey,
		UsageHint: vaultpkg.UsageHintForType(vaultpkg.SecretTypeSSHKey),
	}
}

func (d *cxfItemData) applyCreditCard(raw json.RawMessage) {
	var c cxfCreditCard
	if err := json.Unmarshal(raw, &c); err != nil {
		d.warnings = append(d.warnings, fmt.Sprintf("cxf: credit-card: %v", err))
		return
	}
	month, year := cxfSplitYearMonth(c.ExpiryDate.Value)
	d.data[vaultpkg.PaymentFieldCardNumber] = c.Number.Value
	d.data[vaultpkg.PaymentFieldCardholder] = c.FullName.Value
	d.data[vaultpkg.PaymentFieldExpiryMonth] = month
	d.data[vaultpkg.PaymentFieldExpiryYear] = year
	d.data[vaultpkg.PaymentFieldCVC] = c.VerificationNumber.Value
	d.data[vaultpkg.PaymentFieldSubtype] = string(vaultpkg.PaymentSubtypeCard)
	d.metadata = &vaultpkg.SecretMetadata{
		Type:      vaultpkg.SecretTypePayment,
		UsageHint: vaultpkg.UsageHintForType(vaultpkg.SecretTypePayment),
	}
}

func (d *cxfItemData) skip(ctype string) {
	d.warnings = append(d.warnings, fmt.Sprintf("cxf: skipped credential type %q: not supported by Symaira Vault", ctype))
}

// cxfParseCredential decodes one credential dictionary from its raw JSON and
// returns it together with its type member.
func cxfParseCredential(raw json.RawMessage) (map[string]any, string) {
	var cred map[string]any
	if err := json.Unmarshal(raw, &cred); err != nil {
		return nil, ""
	}
	ctype, ok := cred["type"].(string)
	if !ok {
		ctype = ""
	}
	return cred, ctype
}

// normalizeCXFType canonicalizes a credential type string for comparison:
// "BasicAuth" and "basic-auth" both become "basicauth".
func normalizeCXFType(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	t = strings.ReplaceAll(t, "-", "")
	t = strings.ReplaceAll(t, "_", "")
	return t
}

// cxfTOTPData converts a CXF TOTP credential into the structured totp map
// vault entries carry (the same contract as ParseTOTP, see
// internal/crypto/totp.go). Structured fields are validated with the shared
// crypto gates; secrets that are otpauth URIs are handed to ParseTOTP
// wholesale. Digits and period fall back to the RFC 6238 defaults (6, 30)
// when absent, and unknown algorithms are rejected.
func cxfTOTPData(c cxfTOTP) (map[string]any, error) {
	secret := strings.TrimSpace(c.Secret)
	if secret == "" {
		return nil, fmt.Errorf("empty TOTP secret")
	}
	if strings.HasPrefix(strings.ToLower(secret), "otpauth://") {
		return ParseTOTP(secret)
	}

	algorithm := strings.ToUpper(strings.TrimSpace(c.Algorithm))
	if algorithm == "" {
		algorithm = totpDefaultAlgorithm
	}
	digits := c.Digits
	if digits == 0 {
		digits = totpDefaultDigits
	}
	period := c.Period
	if period == 0 {
		period = totpDefaultPeriod
	}

	if err := crypto.ValidateTOTPSecret(secret); err != nil {
		return nil, fmt.Errorf("invalid TOTP secret: %w", err)
	}
	if err := crypto.ValidateTOTPParams(algorithm, digits, period); err != nil {
		return nil, fmt.Errorf("invalid TOTP configuration: %w", err)
	}
	return map[string]any{
		"secret":    secret,
		"algorithm": algorithm,
		"digits":    float64(digits),
		"period":    float64(period),
	}, nil
}

// cxfSSHKeyMaterial converts a CXF SSH private key into a usable vault
// value. Spec-compliant exports carry the PKCS#8 DER bytes base64url-encoded
// ("privateKey"); draft-era exports carry PEM text ("privateKeyPem"). PEM
// text passes through unchanged; DER blobs are wrapped in a PKCS#8 PEM frame
// so the stored value is directly usable (e.g. with ssh -i).
func cxfSSHKeyMaterial(value string) string {
	if strings.Contains(value, "-----BEGIN") {
		return value
	}
	der, ok := decodeBase64URL(value)
	if !ok || len(der) == 0 {
		return value
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// decodeBase64URL decodes URL-safe base64, tolerating both padded and
// unpadded encodings.
func decodeBase64URL(s string) ([]byte, bool) {
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, true
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, true
	}
	return nil, false
}

// cxfSplitYearMonth splits a CXF "year-month" value (e.g. "2027-08") into
// the vault's expiry month/year fields.
func cxfSplitYearMonth(value string) (month, year string) {
	parts := strings.SplitN(value, "-", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func cxfNonEmptyURLs(urls []string) []string {
	var result []string
	for _, u := range urls {
		if u = strings.TrimSpace(u); u != "" {
			result = append(result, u)
		}
	}
	return result
}

func cxfItemTitle(item cxfItem) string {
	if item.Title != "" {
		return item.Title
	}
	return item.Name
}

func cxfCollectionTitle(collection cxfCollection) string {
	if collection.Title != "" {
		return collection.Title
	}
	return collection.Name
}
