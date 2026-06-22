package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	DefaultArgon2idTime    = 3
	DefaultArgon2idMemory  = 64 * 1024
	DefaultArgon2idThreads = 4
	SaltLen                = 16
	Argon2idKeyLen         = 32
)

type Argon2idParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{
		Time:    DefaultArgon2idTime,
		Memory:  DefaultArgon2idMemory,
		Threads: DefaultArgon2idThreads,
	}
}

func validateArgon2idParams(p Argon2idParams) error {
	if p.Time == 0 {
		return errors.New("argon2id time parameter must be > 0")
	}
	if p.Memory == 0 {
		return errors.New("argon2id memory parameter must be > 0")
	}
	if p.Threads == 0 {
		return errors.New("argon2id threads parameter must be > 0")
	}
	minMem := 4 * uint32(p.Threads)
	if p.Memory < minMem {
		return fmt.Errorf("argon2id memory (%d KiB) must be at least 4*threads (%d KiB)", p.Memory, minMem)
	}
	return nil
}

func (p Argon2idParams) Parallelism() uint8 {
	return p.Threads
}

func resolveArgon2idParams(params Argon2idParams) Argon2idParams {
	if params.Time == 0 && params.Memory == 0 && params.Threads == 0 {
		return DefaultArgon2idParams()
	}
	return params
}

func Argon2idDeriveKey(password, salt []byte, params Argon2idParams) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password is empty")
	}
	if len(salt) == 0 {
		return nil, errors.New("salt is empty")
	}
	params = resolveArgon2idParams(params)
	if err := validateArgon2idParams(params); err != nil {
		return nil, fmt.Errorf("invalid argon2id params: %w", err)
	}
	return argon2.IDKey(password, salt, params.Time, params.Memory, params.Parallelism(), Argon2idKeyLen), nil
}

func GenerateArgon2idSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate argon2id salt: %w", err)
	}
	return salt, nil
}
