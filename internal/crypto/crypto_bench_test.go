package crypto

import (
	"testing"

	"filippo.io/age"
)

func BenchmarkEncrypt_1KB(b *testing.B) {
	benchmarkEncrypt(b, 1024)
}

func BenchmarkEncrypt_10KB(b *testing.B) {
	benchmarkEncrypt(b, 10*1024)
}

func BenchmarkEncrypt_100KB(b *testing.B) {
	benchmarkEncrypt(b, 100*1024)
}

func BenchmarkDecrypt_1KB(b *testing.B) {
	benchmarkDecrypt(b, 1024)
}

func BenchmarkDecrypt_10KB(b *testing.B) {
	benchmarkDecrypt(b, 10*1024)
}

func BenchmarkDecrypt_100KB(b *testing.B) {
	benchmarkDecrypt(b, 100*1024)
}

func BenchmarkGeneratePassword_16_NoSymbols(b *testing.B) {
	benchmarkGeneratePassword(b, 16, false)
}

func BenchmarkGeneratePassword_16_WithSymbols(b *testing.B) {
	benchmarkGeneratePassword(b, 16, true)
}

func BenchmarkGeneratePassword_32_NoSymbols(b *testing.B) {
	benchmarkGeneratePassword(b, 32, false)
}

func BenchmarkGeneratePassword_32_WithSymbols(b *testing.B) {
	benchmarkGeneratePassword(b, 32, true)
}

func BenchmarkGeneratePassword_64_NoSymbols(b *testing.B) {
	benchmarkGeneratePassword(b, 64, false)
}

func BenchmarkGeneratePassword_64_WithSymbols(b *testing.B) {
	benchmarkGeneratePassword(b, 64, true)
}

func benchmarkEncrypt(b *testing.B, size int) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		b.Fatalf("GenerateX25519Identity failed: %v", err)
	}
	recipient := identity.Recipient()
	plaintext := make([]byte, size)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := Encrypt(plaintext, recipient)
		if err != nil {
			b.Fatalf("Encrypt failed: %v", err)
		}
	}
}

func benchmarkDecrypt(b *testing.B, size int) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		b.Fatalf("GenerateX25519Identity failed: %v", err)
	}
	recipient := identity.Recipient()
	plaintext := make([]byte, size)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := Encrypt(plaintext, recipient)
	if err != nil {
		b.Fatalf("Encrypt failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := Decrypt(ciphertext, identity)
		if err != nil {
			b.Fatalf("Decrypt failed: %v", err)
		}
	}
}

func benchmarkGeneratePassword(b *testing.B, length int, useSymbols bool) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, cleanup, err := GeneratePassword(length, useSymbols)
		if cleanup != nil {
			cleanup()
		}
		if err != nil {
			b.Fatalf("GeneratePassword failed: %v", err)
		}
	}
}
