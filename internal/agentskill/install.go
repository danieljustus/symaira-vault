package agentskill

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/danieljustus/OpenPass/internal/pathutil"
)

const backupSuffix = ".bak"

func Install(agentName string, targetPath string, vars TemplateVars, force bool) error {
	if pathutil.HasTraversal(targetPath) {
		return fmt.Errorf("target path contains traversal: %s", targetPath)
	}

	skillData, err := Render(agentName, vars)
	if err != nil {
		return fmt.Errorf("render skill: %w", err)
	}

	existing, err := os.ReadFile(targetPath) // #nosec G304 — validated via ValidatePath
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("read existing skill: %w", err)
		}
		return writeSkill(targetPath, skillData)
	}

	sentinel := FindSentinel(existing)
	if !sentinel {
		if !force {
			return fmt.Errorf("%w: %s", ErrUnmanagedFile, targetPath)
		}
		return writeSkill(targetPath, skillData)
	}

	currentHash, err := computeBodyHashRaw(existing)
	if err != nil {
		return fmt.Errorf("compute current hash: %w", err)
	}

	newHash, err := computeBodyHashRaw(skillData)
	if err != nil {
		return fmt.Errorf("compute new hash: %w", err)
	}

	if currentHash == newHash {
		return nil
	}

	if err := backupFile(targetPath); err != nil {
		return fmt.Errorf("backup skill: %w", err)
	}

	return writeSkill(targetPath, skillData)
}

func Refresh(agentName string, targetPath string, vars TemplateVars) error {
	existing, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("skill not installed: %w", err)
		}
		return fmt.Errorf("read existing skill: %w", err)
	}

	if !FindSentinel(existing) {
		return fmt.Errorf("%w: %s", ErrUnmanagedFile, targetPath)
	}

	return Install(agentName, targetPath, vars, false)
}

func Uninstall(targetPath string) error {
	if pathutil.HasTraversal(targetPath) {
		return fmt.Errorf("target path contains traversal: %s", targetPath)
	}

	existing, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read skill file: %w", err)
	}

	if !FindSentinel(existing) {
		return fmt.Errorf("%w: refusing to delete %s (not managed by openpass)", ErrUnmanagedFile, targetPath)
	}

	if err := os.Remove(targetPath); err != nil {
		return fmt.Errorf("remove skill file: %w", err)
	}
	return nil
}

func Export(agentName string, vars TemplateVars, w io.Writer) error {
	gw := gzip.NewWriter(w)
	defer func() { _ = gw.Close() }()

	tw := tar.NewWriter(gw)
	defer func() { _ = tw.Close() }()

	files, err := renderForExport(agentName, vars)
	if err != nil {
		return err
	}

	for name, data := range files {
		hdr := &tar.Header{
			Name:     name,
			Size:     int64(len(data)),
			Mode:     0o644,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("write tar header for %s: %w", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			return fmt.Errorf("write tar data for %s: %w", name, err)
		}
	}

	return nil
}

func ExportToFile(agentName string, vars TemplateVars, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create export file: %w", err)
	}
	defer func() { _ = f.Close() }()

	return Export(agentName, vars, f)
}

func writeSkill(targetPath string, data []byte) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create skill directory: %w", err)
	}

	if err := os.WriteFile(targetPath, data, 0o644); err != nil {
		return fmt.Errorf("write skill file: %w", err)
	}
	return nil
}

func backupFile(path string) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path+backupSuffix, src, 0o644)
}

func computeBodyHashRaw(data []byte) (string, error) {
	body, err := ExtractBody(data)
	if err != nil {
		return "", err
	}
	return HashBytes(body), nil
}
