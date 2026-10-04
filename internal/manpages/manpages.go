// Package manpages renders Cobra manuals with literal dynamic config paths.
package manpages

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/danieljustus/symaira-vault/internal/config"
)

// GenerateTree retains Cobra's traversal, visibility, filenames,
// headers and Markdown renderer. Only the dynamic configuration path in the MCP
// descriptions is literal data, not user-supplied Markdown.
func GenerateTree(command *cobra.Command, header *doc.GenManHeader, dir string) error {
	for _, child := range command.Commands() {
		if child.IsAvailableCommand() && !child.IsAdditionalHelpTopicCommand() {
			if err := GenerateTree(child, header, dir); err != nil {
				return err
			}
		}
	}
	name := strings.ReplaceAll(command.CommandPath(), " ", "-") + "." + header.Section
	file, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	pageHeader := *header // Cobra fills a separate header for each command.
	return Generate(command, &pageHeader, file)
}

// Generate renders one page, restoring the dynamic description on every exit.
func Generate(command *cobra.Command, header *doc.GenManHeader, writer io.Writer) error {
	if command.Parent() != command.Root() || (command.Name() != "mcp" && command.Name() != "serve") {
		return doc.GenMan(command, header, writer)
	}
	path := filepath.Join(config.DefaultConfigDir(), "config.yaml")
	description := command.Long
	if strings.Count(description, path) != 1 {
		return fmt.Errorf("manual description must contain exactly one resolved configuration path")
	}
	// Alphanumeric markers cannot become Markdown syntax. Avoid collisions even
	// when a user's actual path contains the marker; never replace arbitrary docs.
	marker := "SYMVAULTLITERALCONFIGPATH"
	for index := 0; strings.Contains(description+command.Short+command.Example, marker); index++ {
		marker = "SYMVAULTLITERALCONFIGPATH" + strconv.Itoa(index)
	}
	command.Long = strings.Replace(description, path, marker, 1)
	defer func() { command.Long = description }() // help remains byte-identical
	var page bytes.Buffer
	if err := doc.GenMan(command, header, &page); err != nil {
		return err
	}
	if bytes.Count(page.Bytes(), []byte(marker)) != 1 {
		return fmt.Errorf("manual configuration marker must occur exactly once")
	}
	_, err := writer.Write(bytes.ReplaceAll(page.Bytes(), []byte(marker), []byte(LiteralText(path))))
	return err
}

// LiteralText escapes roff syntax, not Markdown. Control characters are
// displayed as visible Go-style escapes, so no path can introduce a roff line or
// request. Spaces and printable Unicode remain literal. Protect a leading dot
// or apostrophe even if this helper is later used at the start of a roff line.
func LiteralText(text string) string {
	var out strings.Builder
	if strings.HasPrefix(text, ".") || strings.HasPrefix(text, "'") {
		out.WriteString(`\&`)
	}
	for _, char := range text {
		switch {
		case unicode.IsControl(char) || char == '\u2028' || char == '\u2029':
			quoted := strconv.QuoteRune(char)
			out.WriteString(strings.ReplaceAll(quoted[1:len(quoted)-1], `\`, `\\`))
		case char == '\\':
			out.WriteString(`\\`)
		default:
			out.WriteRune(char)
		}
	}
	return out.String()
}
