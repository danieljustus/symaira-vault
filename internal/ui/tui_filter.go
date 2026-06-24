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
	if m.sortMode == 0 || m.sortMode == 1 {
		sort.SliceStable(m.filtered, func(i, j int) bool {
			if m.sortMode == 0 {
				return m.filtered[i] < m.filtered[j]
			}
			return m.filtered[i] > m.filtered[j]
		})
		return
	}
	m.ensureMetaCache()
	sort.SliceStable(m.filtered, func(i, j int) bool {
		mi := m.metaCache[m.filtered[i]]
		mj := m.metaCache[m.filtered[j]]
		if m.sortMode == 2 {
			return mi.Updated.Before(mj.Updated)
		}
		return mi.Updated.After(mj.Updated)
	})
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
	switch m.sortMode {
	case 0:
		return "name\u2191"
	case 1:
		return "name\u2193"
	case 2:
		return "updated\u2191"
	default:
		return "updated\u2193"
	}
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
