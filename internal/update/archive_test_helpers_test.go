package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
)

// buildTestTarGz creates an in-memory tar.gz archive containing the given
// entries. Each entry is a path to content mapping.
func buildTestTarGz(entries map[string]string, dirMode bool) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for path, content := range entries {
		if dirMode && content == "" {
			_ = tw.WriteHeader(&tar.Header{
				Name:     path,
				Typeflag: tar.TypeDir,
				Mode:     0o755,
			})
		} else {
			_ = tw.WriteHeader(&tar.Header{
				Name:     path,
				Typeflag: tar.TypeReg,
				Mode:     0o755,
				Size:     int64(len(content)),
			})
			_, _ = tw.Write([]byte(content))
		}
	}

	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}
