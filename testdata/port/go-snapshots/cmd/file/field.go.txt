package file

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
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

// decodeAttachmentContent extracts and decodes binary attachment content from an entry's field.
// If the stored value is a "chunked-v1:" manifest, the chunks listed are resolved from
// the same entry's Data map, concatenated in order, and decoded from base64.
func decodeAttachmentContent(entry *vaultpkg.Entry, resolvedField string) ([]byte, error) {
	raw, ok := entry.Data[resolvedField]
	if !ok {
		if entry.Path != "" {
			return nil, errorspkg.NewCLIError(errorspkg.ExitNotFound, fmt.Sprintf("field %q not found in entry %q", resolvedField, entry.Path), nil)
		}
		return nil, errorspkg.NewCLIError(errorspkg.ExitNotFound, fmt.Sprintf("field %q not found in entry", resolvedField), nil)
	}
	encoded, ok := raw.(string)
	if !ok {
		return nil, errorspkg.NewCLIError(errorspkg.ExitGeneralError, fmt.Sprintf("field %q is not string-encoded content", resolvedField), nil)
	}

	if strings.HasPrefix(encoded, "chunked-v1:") {
		manifest := strings.TrimPrefix(encoded, "chunked-v1:")
		if manifest == "" {
			return nil, errorspkg.NewCLIError(errorspkg.ExitGeneralError, fmt.Sprintf("invalid chunk manifest in field %q: no chunks specified", resolvedField), nil)
		}
		chunkNames := strings.Split(manifest, ",")

		for _, countKey := range []string{resolvedField + "_chunk_count", "chunk_count"} {
			if countRaw, ok := entry.Data[countKey]; ok {
				var expectedCount int
				switch v := countRaw.(type) {
				case int:
					expectedCount = v
				case int64:
					expectedCount = int(v)
				case float64:
					expectedCount = int(v)
				case string:
					if p, err := strconv.Atoi(v); err == nil {
						expectedCount = p
					}
				}
				if expectedCount > 0 && expectedCount != len(chunkNames) {
					return nil, errorspkg.NewCLIError(errorspkg.ExitGeneralError,
						fmt.Sprintf("chunk count mismatch for field %q: manifest lists %d chunks, entry specifies %d", resolvedField, len(chunkNames), expectedCount), nil)
				}
			}
		}

		var sb strings.Builder
		for _, chunkName := range chunkNames {
			chunkName = strings.TrimSpace(chunkName)
			if chunkName == "" {
				return nil, errorspkg.NewCLIError(errorspkg.ExitGeneralError, fmt.Sprintf("invalid chunk manifest in field %q: empty chunk name", resolvedField), nil)
			}
			chunkRaw, ok := entry.Data[chunkName]
			if !ok {
				return nil, errorspkg.NewCLIError(errorspkg.ExitNotFound, fmt.Sprintf("chunk field %q not found in entry", chunkName), nil)
			}
			chunkStr, ok := chunkRaw.(string)
			if !ok {
				return nil, errorspkg.NewCLIError(errorspkg.ExitGeneralError, fmt.Sprintf("chunk field %q is not string-encoded content", chunkName), nil)
			}
			sb.WriteString(chunkStr)
		}

		content, decErr := base64.StdEncoding.DecodeString(sb.String())
		if decErr != nil {
			return nil, errorspkg.Wrap(errorspkg.ExitGeneralError, errorspkg.ErrKindNone, decErr, "decode attachment content")
		}
		return content, nil
	}

	content, decErr := base64.StdEncoding.DecodeString(encoded)
	if decErr != nil {
		return nil, errorspkg.Wrap(errorspkg.ExitGeneralError, errorspkg.ErrKindNone, decErr, "decode attachment content")
	}
	return content, nil
}
