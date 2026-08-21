package session

import (
	"errors"
	"fmt"
)

// macOS Security framework OSStatus values returned by the Keychain
// Services calls in touchid_darwin.go. They are declared here (rather than
// in the cgo file) so the status-to-error mapping and its tests build on
// every platform.
const (
	errSecSuccess               = 0
	errSecUnimplemented         = -4
	errSecParam                 = -50
	errSecAllocate              = -108
	errSecUserCanceled          = -128
	errSecNotAvailable          = -25291
	errSecReadOnly              = -25292
	errSecAuthFailed            = -25293
	errSecNoSuchKeychain        = -25294
	errSecInvalidKeychain       = -25295
	errSecDuplicateItem         = -25299
	errSecItemNotFound          = -25300
	errSecInteractionNotAllowed = -25308
	errSecDecode                = -26275
	errSecMissingEntitlement    = -34018
)

// Keychain failures that have nothing to do with biometrics. Reporting
// these as ErrBiometricFailed sends users hunting for a Touch ID problem
// that does not exist, so each gets its own sentinel callers can match.
var (
	ErrKeychainDuplicateItem         = errors.New("keychain item already exists")
	ErrKeychainItemNotFound          = errors.New("keychain item not found")
	ErrKeychainNoSuchKeychain        = errors.New("keychain not found")
	ErrKeychainInvalid               = errors.New("keychain is invalid or corrupted")
	ErrKeychainLocked                = errors.New("keychain is locked or unavailable")
	ErrKeychainReadOnly              = errors.New("keychain is read-only")
	ErrKeychainInteractionNotAllowed = errors.New("keychain access requires user interaction")
	ErrKeychainMissingEntitlement    = errors.New("keychain access denied for this binary")
	ErrKeychainInternal              = errors.New("keychain call failed")
	ErrKeychainUnexpectedStatus      = errors.New("unexpected keychain error")
)

// doctorHint points at the doctor check that already diagnoses a keychain
// search list which does not contain the default keychain — the usual
// cause of writes and lookups disagreeing about where an item lives.
const doctorHint = "run `symvault doctor` and check the \"Session keyring roundtrip\" result"

// searchListHint explains the failure mode doctor detects, for the
// statuses that are produced by it.
const searchListHint = "the login keychain may be missing from the keychain search list (`security list-keychains -d user`), so writes and lookups target different keychains — " + doctorHint

type keychainStatusMapping struct {
	// err is the sentinel wrapped into the returned error.
	err error
	// detail explains what the status means in this context.
	detail string
	// hint names the next concrete action, when one exists.
	hint string
}

var keychainStatusMappings = map[int]keychainStatusMapping{
	errSecDuplicateItem: {
		err:    ErrKeychainDuplicateItem,
		detail: "the existing item could not be replaced",
		hint:   searchListHint,
	},
	errSecItemNotFound: {
		err:    ErrKeychainItemNotFound,
		detail: "no matching item is visible to this process",
		hint:   searchListHint,
	},
	errSecNoSuchKeychain: {
		err:    ErrKeychainNoSuchKeychain,
		detail: "the target keychain does not exist",
		hint:   searchListHint,
	},
	errSecInvalidKeychain: {
		err:    ErrKeychainInvalid,
		detail: "the target keychain could not be read",
		hint:   doctorHint,
	},
	errSecNotAvailable: {
		err:    ErrKeychainLocked,
		detail: "no keychain is available to this process",
		hint:   "unlock the login keychain with `security unlock-keychain` and re-run the command from a logged-in session",
	},
	errSecReadOnly: {
		err:    ErrKeychainReadOnly,
		detail: "the keychain does not accept writes",
		hint:   "unlock the login keychain with `security unlock-keychain` and check its permissions in Keychain Access",
	},
	errSecInteractionNotAllowed: {
		err:    ErrKeychainInteractionNotAllowed,
		detail: "the keychain is locked and this process cannot prompt",
		hint:   "unlock the login keychain with `security unlock-keychain` and re-run the command from a logged-in GUI session",
	},
	errSecMissingEntitlement: {
		err:    ErrKeychainMissingEntitlement,
		detail: "the running binary lacks the entitlement or signature the keychain item requires",
		hint:   "use an official signed `symvault` build, or re-create the item with the binary you are running",
	},
	errSecAuthFailed: {
		err:    ErrBiometricFailed,
		detail: "the system rejected the authentication",
		hint:   "retry, or fall back to `symvault unlock` with your passphrase",
	},
	errSecUserCanceled: {
		err:    ErrBiometricFailed,
		detail: "the authentication prompt was canceled",
		hint:   "retry and complete the Touch ID prompt",
	},
	errSecDecode: {
		err:    ErrKeychainInvalid,
		detail: "the stored item could not be decoded",
		hint:   "re-run `symvault auth set touchid` to store the passphrase again",
	},
	errSecParam: {
		err:    ErrKeychainInternal,
		detail: "the keychain rejected the request parameters",
	},
	errSecAllocate: {
		err:    ErrKeychainInternal,
		detail: "the keychain could not allocate memory",
	},
	errSecUnimplemented: {
		err:    ErrKeychainInternal,
		detail: "the keychain operation is not implemented on this system",
	},
}

// keychainStatusError converts a macOS OSStatus into a descriptive Go
// error, or nil for errSecSuccess. Only statuses that genuinely describe a
// failed biometric factor wrap ErrBiometricFailed; everything else wraps a
// keychain sentinel so the message names the real cause.
func keychainStatusError(status int) error {
	if status == errSecSuccess {
		return nil
	}
	mapping, ok := keychainStatusMappings[status]
	if !ok {
		mapping = keychainStatusMapping{err: ErrKeychainUnexpectedStatus, hint: doctorHint}
	}

	suffix := ""
	if mapping.detail != "" {
		suffix = ": " + mapping.detail
	}
	suffix += fmt.Sprintf(" (keychain status %d)", status)
	if mapping.hint != "" {
		suffix += "; " + mapping.hint
	}
	return fmt.Errorf("%w%s", mapping.err, suffix)
}
