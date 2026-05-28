// Package safepath provides symlink-safe file I/O interfaces with platform-specific
// implementations for Unix and Windows. It defines SafeWriter and SafeRemover
// interfaces that guarantee no symlink traversal or non-regular file operations,
// and a concrete Manager that delegates to the existing fsutil primitives.
//
// The interfaces allow callers (notably the vault package) to depend on
// abstractions rather than platform-specific syscall code. The DefaultManager
// wraps the symlink-hardened functions already proven in production via the
// internal/fsutil and internal/vault packages.
//
// Platform support matrix:
//
//	Platform  Backend      SafeWriteFile  SafeRemove  SafeMkdirAll
//	Unix      O_NOFOLLOW   ✓              ✓           ✓ (component walk)
//	Windows   os.Lstat     ✓              ✓           ✓ (component walk)
//
// Fuzz tests in fuzz_test.go generate random path trees with symlinks and verify
// no traversal occurs.
package safepath
