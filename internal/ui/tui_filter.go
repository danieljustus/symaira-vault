package ui

import (
	"sort"
	"strings"

	"github.com/mattn/go-runewidth"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func (m *TUIModel) applyFilter() {
	query := strings.TrimSpace(m.filterInput.Value())
	m.filtered = m.filtered[:0]
	for _, entry := range m.entries {
		if fuzzyMatch(query, entry) && m.tagMatch(entry) {
			m.filtered = append(m.filtered, entry)
		}
	}
	m.sortFiltered()
	if m.selected >= len(m.filtered) {
		m.selected = max(0, len(m.filtered)-1)
	}
}

func (m *TUIModel) ensureMetaCache() {
	if m.metaCache == nil {
		m.metaCache = make(map[string]vaultpkg.EntryMetadata)
	}
	for _, path := range m.entries {
		if _, ok := m.metaCache[path]; ok {
			continue
		}
		meta, err := vaultpkg.GetEntryMetadata(m.vault.Dir, path, m.vault.Identity)
		if err != nil {
			continue
		}
		m.metaCache[path] = *meta
	}
}

func (m TUIModel) tagMatch(entry string) bool {
	if m.filterTag == "" {
		return true
	}
	meta, ok := m.metaCache[entry]
	if !ok {
		return false
	}
	for _, tag := range meta.Tags {
		if strings.HasPrefix(strings.ToLower(tag), strings.ToLower(m.filterTag)) {
			return true
		}
	}
	return false
}

func (m *TUIModel) sortFiltered() {
	switch m.sortMode {
	case 0, 1:
		sort.SliceStable(m.filtered, func(i, j int) bool {
			if m.sortMode == 0 {
				return m.filtered[i] < m.filtered[j]
			}
			return m.filtered[i] > m.filtered[j]
		})
	case 2, 3:
		m.ensureMetaCache()
		sort.SliceStable(m.filtered, func(i, j int) bool {
			mi := m.metaCache[m.filtered[i]]
			mj := m.metaCache[m.filtered[j]]
			if m.sortMode == 2 {
				return mi.Updated.Before(mj.Updated)
			}
			return mi.Updated.After(mj.Updated)
		})
	default:
		m.sortByType(m.sortMode == 5)
	}
}

func (m *TUIModel) ensureSecretTypeCache() {
	if m.secretTypeCache == nil {
		m.secretTypeCache = make(map[string]vaultpkg.SecretType)
	}
	for _, path := range m.filtered {
		if _, ok := m.secretTypeCache[path]; ok {
			continue
		}
		entry, err := vaultpkg.ReadEntry(m.vault.Dir, path, m.vault.Identity)
		if err != nil {
			m.secretTypeCache[path] = vaultpkg.SecretTypeCustom
			continue
		}
		t := entry.SecretMetadata.Type
		if t == "" {
			t = vaultpkg.SecretTypeCustom
		}
		m.secretTypeCache[path] = t
	}
}

func (m *TUIModel) sortByType(reverse bool) {
	m.ensureSecretTypeCache()

	typeOrder := map[vaultpkg.SecretType]int{
		vaultpkg.SecretTypeAPIKey:      0,
		vaultpkg.SecretTypeBearerToken: 1,
		vaultpkg.SecretTypeSSHKey:      2,
		vaultpkg.SecretTypePassword:    3,
		vaultpkg.SecretTypeDatabaseURL: 4,
		vaultpkg.SecretTypeCertificate: 5,
		vaultpkg.SecretTypeTOTPSeed:    6,
		vaultpkg.SecretTypeBasicAuth:   7,
		vaultpkg.SecretTypeCustom:      8,
	}

	sort.SliceStable(m.filtered, func(i, j int) bool {
		ti := m.secretTypeCache[m.filtered[i]]
		tj := m.secretTypeCache[m.filtered[j]]
		oi := typeOrder[ti]
		oj := typeOrder[tj]
		if oi == oj {
			return m.filtered[i] < m.filtered[j]
		}
		if reverse {
			return oi > oj
		}
		return oi < oj
	})
}

func (m *TUIModel) typeCount(t vaultpkg.SecretType) int {
	count := 0
	for _, path := range m.filtered {
		if m.secretTypeCache[path] == t {
			count++
		}
	}
	return count
}

func (m TUIModel) availableTags() []string {
	tagSet := make(map[string]struct{})
	for _, meta := range m.metaCache {
		for _, tag := range meta.Tags {
			tagSet[tag] = struct{}{}
		}
	}
	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

func (m TUIModel) sortLabel() string {
	labels := []string{"name\u2191", "name\u2193", "updated\u2191", "updated\u2193", "type\u2191", "type\u2193"}
	if m.sortMode >= 0 && m.sortMode < len(labels) {
		return labels[m.sortMode]
	}
	return labels[0]
}

func fuzzyMatch(query, value string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	value = strings.ToLower(value)
	if strings.Contains(value, query) {
		return true
	}
	queryRunes := []rune(query)
	idx := 0
	for _, r := range value {
		if idx < len(queryRunes) && r == queryRunes[idx] {
			idx++
		}
	}
	return idx == len(queryRunes)
}

func isSensitiveField(field string) bool {
	field = strings.ToLower(field)
	return strings.Contains(field, "pass") ||
		strings.Contains(field, "secret") ||
		strings.Contains(field, "token") ||
		strings.Contains(field, "key") ||
		strings.Contains(field, "otp") ||
		strings.Contains(field, "pin") ||
		strings.Contains(field, "backup") ||
		strings.Contains(field, "seed")
}

func truncate(value string, width int) string {
	if width <= 1 {
		return value
	}
	if runewidth.StringWidth(value) <= width {
		return value
	}
	return runewidth.Truncate(value, width, "\u2026")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
