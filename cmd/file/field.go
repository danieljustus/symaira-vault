package file

import (
	"fmt"
	"sort"
	"strings"

	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// splitPathField splits "path#field" into its two parts. field is empty
// when arg has no "#" separator.
func splitPathField(arg string) (path, field string) {
	if idx := strings.LastIndex(arg, "#"); idx > 0 {
		return arg[:idx], arg[idx+1:]
	}
	return arg, ""
}

// resolveAttachmentField picks the attachment field to act on: explicitField
// when given (attachment metadata is looked up but its absence is not an
// error, since --field may point at a field added outside `file add`),
// or the entry's only recorded attachment when there is exactly one,
// otherwise an error listing the available fields.
func resolveAttachmentField(entry *vaultpkg.Entry, explicitField string) (field string, info *vaultpkg.AttachmentInfo, err error) {
	if explicitField != "" {
		if got, ok := entry.SecretMetadata.Attachments[explicitField]; ok {
			return explicitField, &got, nil
		}
		return explicitField, nil, nil
	}

	switch len(entry.SecretMetadata.Attachments) {
	case 0:
		return "", nil, errorspkg.NewCLIError(errorspkg.ExitInvalidInput, "entry has no recorded attachment fields; specify --field", nil)
	case 1:
		for name, got := range entry.SecretMetadata.Attachments {
			gotCopy := got
			return name, &gotCopy, nil
		}
	}

	names := make([]string, 0, len(entry.SecretMetadata.Attachments))
	for name := range entry.SecretMetadata.Attachments {
		names = append(names, name)
	}
	sort.Strings(names)
	return "", nil, errorspkg.NewCLIError(errorspkg.ExitInvalidInput,
		fmt.Sprintf("entry has multiple attachment fields (%s); specify --field", strings.Join(names, ", ")), nil)
}
