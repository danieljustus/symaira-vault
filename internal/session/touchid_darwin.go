//go:build darwin && cgo

package session

/*
#cgo CFLAGS: -x objective-c -Wno-deprecated-declarations
#cgo LDFLAGS: -framework LocalAuthentication -framework Security -framework Foundation

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>
#import <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>

int touch_id_available() {
	LAContext *context = [[LAContext alloc] init];
	if (context == nil) {
		return 0;
	}
	NSError *error = nil;
	BOOL canEvaluate = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
	[context release];
	return canEvaluate ? 1 : 0;
}

int touch_id_authenticate(char *reason) {
	LAContext *context = [[LAContext alloc] init];
	if (context == nil) {
		return -1;
	}
	NSError *error = nil;
	BOOL canEval = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
	if (!canEval) {
		[context release];
		return -2;
	}

	__block int result = 0;
	dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
	[context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
	        localizedReason:[NSString stringWithUTF8String:reason]
	                  reply:^(BOOL success, NSError *replyError) {
		result = success ? 1 : 0;
		dispatch_semaphore_signal(semaphore);
	}];
	dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
	[semaphore release];
	[context release];
	return result;
}

static CFMutableDictionaryRef symaira_biometric_query(char *service_c, char *account_c) {
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (query == NULL) {
		return NULL;
	}

	CFStringRef service = CFStringCreateWithCString(NULL, service_c, kCFStringEncodingUTF8);
	CFStringRef account = CFStringCreateWithCString(NULL, account_c, kCFStringEncodingUTF8);
	if (service == NULL || account == NULL) {
		if (service != NULL) {
			CFRelease(service);
		}
		if (account != NULL) {
			CFRelease(account);
		}
		CFRelease(query);
		return NULL;
	}

	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, service);
	CFDictionarySetValue(query, kSecAttrAccount, account);

	CFRelease(service);
	CFRelease(account);
	return query;
}

int touch_id_store_passphrase(char *service_c, char *account_c, char *passphrase_c) {
	CFMutableDictionaryRef query = symaira_biometric_query(service_c, account_c);
	if (query == NULL) {
		return errSecParam;
	}

	SecItemDelete(query);

	CFDataRef data = CFDataCreate(NULL, (const UInt8 *)passphrase_c, (CFIndex)strlen(passphrase_c));
	if (data == NULL) {
		CFRelease(query);
		return errSecParam;
	}

	CFDictionarySetValue(query, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
	CFDictionarySetValue(query, kSecValueData, data);

	OSStatus status = SecItemAdd(query, NULL);
	CFRelease(data);
	CFRelease(query);
	return (int)status;
}

int touch_id_load_passphrase(char *service_c, char *account_c, char *reason_c, char **passphrase_out) {
	if (passphrase_out == NULL) {
		return errSecParam;
	}
	*passphrase_out = NULL;

	CFMutableDictionaryRef checkQuery = symaira_biometric_query(service_c, account_c);
	if (checkQuery == NULL) {
		return errSecParam;
	}
	CFDictionarySetValue(checkQuery, kSecReturnData, kCFBooleanFalse);
	CFDictionarySetValue(checkQuery, kSecMatchLimit, kSecMatchLimitOne);

	CFTypeRef checkResult = NULL;
	OSStatus checkStatus = SecItemCopyMatching(checkQuery, &checkResult);
	CFRelease(checkQuery);
	if (checkResult != NULL) {
		CFRelease(checkResult);
	}
	if (checkStatus == errSecItemNotFound) {
		return errSecItemNotFound;
	}
	if (checkStatus != errSecSuccess) {
		return (int)checkStatus;
	}

	LAContext *laCtx = [[LAContext alloc] init];
	if (laCtx == nil) {
		return errSecAuthFailed;
	}
	NSError *laError = nil;
	BOOL canEval = [laCtx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
	                                  error:&laError];
	if (!canEval) {
		[laCtx release];
		return errSecAuthFailed;
	}

	__block int authResult = 0;
	dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
	[laCtx evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
	      localizedReason:[NSString stringWithUTF8String:reason_c]
	                reply:^(BOOL success, NSError *replyError) {
		authResult = success ? 1 : 0;
		dispatch_semaphore_signal(semaphore);
	}];
	long waitResult = dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC));
	[semaphore release];
	[laCtx release];

	if (waitResult != 0) {
		return errSecAuthFailed;
	}
	if (authResult != 1) {
		return errSecAuthFailed;
	}

	CFMutableDictionaryRef query = symaira_biometric_query(service_c, account_c);
	if (query == NULL) {
		return errSecParam;
	}

	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
	if (status != errSecSuccess) {
		return (int)status;
	}
	if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
		if (result != NULL) {
			CFRelease(result);
		}
		return errSecParam;
	}

	CFDataRef data = (CFDataRef)result;
	CFIndex len = CFDataGetLength(data);
	char *out = (char *)malloc((size_t)len + 1);
	if (out == NULL) {
		CFRelease(result);
		return errSecAllocate;
	}
	memcpy(out, CFDataGetBytePtr(data), (size_t)len);
	out[len] = '\0';
	*passphrase_out = out;
	CFRelease(result);
	return errSecSuccess;
}

int touch_id_delete_passphrase(char *service_c, char *account_c) {
	CFMutableDictionaryRef query = symaira_biometric_query(service_c, account_c);
	if (query == NULL) {
		return errSecParam;
	}
	OSStatus status = SecItemDelete(query);
	CFRelease(query);
	if (status == errSecItemNotFound) {
		return errSecSuccess;
	}
	return (int)status;
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
)

var errTouchIDNotAvailable = errors.New("touch id not available")
var errTouchIDFailed = errors.New("touch id authentication failed")

const (
	errSecSuccess      = 0
	errSecItemNotFound = -25300
)

func touchIDAvailable() bool {
	return C.touch_id_available() == 1
}

func touchIDAuthenticate(ctx context.Context, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !touchIDAvailable() {
		return errTouchIDNotAvailable
	}
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	result := C.touch_id_authenticate(cReason)
	if result == 1 {
		return nil
	}
	return errTouchIDFailed
}

type touchIDAuthenticator struct{}

func (t *touchIDAuthenticator) Authenticate(ctx context.Context, reason string) error {
	return touchIDAuthenticate(ctx, reason)
}

func (t *touchIDAuthenticator) IsAvailable() bool {
	return touchIDAvailable()
}

func newTouchIDAuthenticator() BiometricAuthenticator {
	return &touchIDAuthenticator{}
}

const biometricAccount = "passphrase"

const (
	currentBiometricServicePrefix = "symvault-biometric:"
	legacyBiometricServicePrefix  = "openpass-biometric:"
)

func biometricServiceName(vaultDir string) string {
	return currentBiometricServicePrefix + vaultDir
}

func biometricServiceNames(vaultDir string) []string {
	candidates := []string{
		currentBiometricServicePrefix + vaultDir,
		legacyBiometricServicePrefix + vaultDir,
	}

	if legacyDir := legacyDefaultVaultDir(vaultDir); legacyDir != "" && legacyDir != vaultDir {
		candidates = append(candidates,
			currentBiometricServicePrefix+legacyDir,
			legacyBiometricServicePrefix+legacyDir,
		)
	}

	return uniqueServices(candidates...)
}

func biometricDeleteServiceNames(vaultDir string) []string {
	return uniqueServices(
		currentBiometricServicePrefix+vaultDir,
		legacyBiometricServicePrefix+vaultDir,
	)
}

func uniqueServices(candidates ...string) []string {
	var services []string
	for _, service := range candidates {
		if service == "" {
			continue
		}
		exists := false
		for _, existing := range services {
			if existing == service {
				exists = true
				break
			}
		}
		if !exists {
			services = append(services, service)
		}
	}
	return services
}

func legacyDefaultVaultDir(vaultDir string) string {
	clean := filepath.Clean(vaultDir)
	if filepath.Base(clean) != configpkg.DefaultVaultSubdir {
		return ""
	}
	return filepath.Join(filepath.Dir(clean), configpkg.LegacyDefaultVaultSubdir)
}

type touchIDPassphraseStore struct{}

func (t *touchIDPassphraseStore) IsAvailable() bool {
	return touchIDAvailable()
}

func (t *touchIDPassphraseStore) Save(ctx context.Context, vaultDir string, passphrase []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !touchIDAvailable() {
		return ErrBiometricNotAvailable
	}

	service := C.CString(biometricServiceName(vaultDir))
	account := C.CString(biometricAccount)
	secret := C.CString(string(passphrase))
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	defer C.free(unsafe.Pointer(secret))

	if status := int(C.touch_id_store_passphrase(service, account, secret)); status != errSecSuccess {
		return fmt.Errorf("%w: keychain status %d", ErrBiometricFailed, status)
	}
	return nil
}

func (t *touchIDPassphraseStore) Load(ctx context.Context, vaultDir string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !touchIDAvailable() {
		return nil, ErrBiometricNotAvailable
	}

	var lastNotConfigured error
	for _, serviceName := range biometricServiceNames(vaultDir) {
		passphrase, err := t.loadFromService(serviceName)
		if err == nil {
			return passphrase, nil
		}
		if errors.Is(err, ErrBiometricNotConfigured) {
			lastNotConfigured = err
			continue
		}
		return nil, err
	}
	if lastNotConfigured != nil {
		return nil, lastNotConfigured
	}
	return nil, ErrBiometricNotConfigured
}

func (t *touchIDPassphraseStore) loadFromService(serviceName string) ([]byte, error) {
	service := C.CString(serviceName)
	account := C.CString(biometricAccount)
	reason := C.CString("Unlock Symaira Vault vault")
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	defer C.free(unsafe.Pointer(reason))

	var out *C.char
	status := int(C.touch_id_load_passphrase(service, account, reason, &out)) //nolint:gocritic // Cgo call, dupSubExpr false positive
	if status == errSecItemNotFound {
		return nil, ErrBiometricNotConfigured
	}
	if status != errSecSuccess {
		return nil, fmt.Errorf("%w: keychain status %d", ErrBiometricFailed, status)
	}
	goStr := C.GoString(out)
	// Wipe the C string memory before freeing
	C.memset(unsafe.Pointer(out), 0, C.size_t(len(goStr)))
	C.free(unsafe.Pointer(out))

	return []byte(goStr), nil
}

func (t *touchIDPassphraseStore) Delete(vaultDir string) error {
	var firstErr error
	for _, serviceName := range biometricDeleteServiceNames(vaultDir) {
		if err := t.deleteFromService(serviceName); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (t *touchIDPassphraseStore) deleteFromService(serviceName string) error {
	service := C.CString(serviceName)
	account := C.CString(biometricAccount)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))

	if status := int(C.touch_id_delete_passphrase(service, account)); status != errSecSuccess {
		return fmt.Errorf("%w: keychain status %d", ErrBiometricFailed, status)
	}
	return nil
}

func init() {
	biometricAuthenticator = newTouchIDAuthenticator()
	biometricPassphraseStore = &touchIDPassphraseStore{}
}
