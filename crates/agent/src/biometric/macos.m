#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static NSString *const kSiloKeychainService = @"dev.silo.biometric-unlock";
static NSString *const kSiloKeychainLabel = @"Silo Vault Biometric Unlock Key";

static LAPolicy silo_biometric_policy(void) {
    return LAPolicyDeviceOwnerAuthenticationWithBiometrics;
}

static void copy_message(NSString *message, char *buf, size_t len) {
    if (buf == NULL || len == 0) {
        return;
    }
    if (message == nil) {
        buf[0] = '\0';
        return;
    }
    const char *utf8 = [message UTF8String];
    if (utf8 == NULL) {
        buf[0] = '\0';
        return;
    }
    strlcpy(buf, utf8, len);
}

static void copy_osstatus(OSStatus status, char *buf, size_t len) {
    CFStringRef desc = SecCopyErrorMessageString(status, NULL);
    if (desc != NULL) {
        NSString *msg = CFBridgingRelease(desc);
        copy_message(msg, buf, len);
    } else {
        NSString *msg = [NSString stringWithFormat:@"Keychain error (%d)", (int)status];
        copy_message(msg, buf, len);
    }
}

bool silo_biometric_available(void) {
    @autoreleasepool {
        LAContext *ctx = [[LAContext alloc] init];
        NSError *err = nil;
        BOOL ok = [ctx canEvaluatePolicy:silo_biometric_policy() error:&err];
        [ctx invalidate];
        return ok ? true : false;
    }
}

/*
 * Return codes:
 *   0 = authenticated
 *   1 = cancelled
 *   2 = unavailable
 *   3 = failed
 */
int silo_biometric_authenticate(const char *reason, char *err_buf, size_t err_len) {
    @autoreleasepool {
        LAContext *ctx = [[LAContext alloc] init];
        // Keep fallback in Silo (master password) rather than the macOS login password.
        ctx.localizedFallbackTitle = @"";
        LAPolicy policy = silo_biometric_policy();
        NSError *canErr = nil;
        if (![ctx canEvaluatePolicy:policy error:&canErr]) {
            copy_message(canErr.localizedDescription ?: @"Touch ID is not available", err_buf, err_len);
            [ctx invalidate];
            return 2;
        }

        NSString *nsReason = reason != NULL
            ? [NSString stringWithUTF8String:reason]
            : @"unlock your Silo vault";
        if (nsReason == nil || nsReason.length == 0) {
            nsReason = @"unlock your Silo vault";
        }

        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        __block int code = 3;
        __block NSString *failureMessage = nil;

        [ctx evaluatePolicy:policy localizedReason:nsReason reply:^(BOOL success, NSError *error) {
            if (success) {
                code = 0;
            } else if (error != nil) {
                failureMessage = error.localizedDescription;
                switch (error.code) {
                    case LAErrorUserCancel:
                    case LAErrorSystemCancel:
                    case LAErrorAppCancel:
                    case LAErrorUserFallback:
                        code = 1;
                        break;
                    case LAErrorBiometryNotAvailable:
                    case LAErrorBiometryNotEnrolled:
                    case LAErrorBiometryLockout:
                    case LAErrorPasscodeNotSet:
                        code = 2;
                        break;
                    default:
                        code = 3;
                        break;
                }
            } else {
                code = 3;
                failureMessage = @"biometric authentication failed";
            }
            dispatch_semaphore_signal(sem);
        }];

        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        [ctx invalidate];
        if (code != 0) {
            copy_message(failureMessage, err_buf, err_len);
        }
        return code;
    }
}

/*
 * Return codes:
 *   0 = ok
 *   2 = error
 */
int silo_keychain_store(
    const char *account,
    const uint8_t *key,
    size_t key_len,
    char *err_buf,
    size_t err_len
) {
    @autoreleasepool {
        if (account == NULL || key == NULL || key_len == 0) {
            copy_message(@"invalid keychain parameters", err_buf, err_len);
            return 2;
        }
        NSString *nsAccount = [NSString stringWithUTF8String:account];
        if (nsAccount == nil) {
            copy_message(@"invalid keychain account string", err_buf, err_len);
            return 2;
        }

        NSDictionary *query = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService: kSiloKeychainService,
            (__bridge id)kSecAttrAccount: nsAccount,
        };
        SecItemDelete((__bridge CFDictionaryRef)query);

        NSMutableData *secret = [NSMutableData dataWithBytes:key length:key_len];
        NSDictionary *attrs = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService: kSiloKeychainService,
            (__bridge id)kSecAttrAccount: nsAccount,
            (__bridge id)kSecAttrLabel: kSiloKeychainLabel,
            (__bridge id)kSecValueData: secret,
        };
        OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attrs, NULL);
        if (secret.mutableBytes != NULL && secret.length > 0) {
            memset_s(secret.mutableBytes, secret.length, 0, secret.length);
        }
        if (status != errSecSuccess) {
            copy_osstatus(status, err_buf, err_len);
            return 2;
        }
        return 0;
    }
}

/*
 * Return codes:
 *   0 = ok
 *   1 = not found
 *   2 = error
 */
int silo_keychain_load(
    const char *account,
    uint8_t *out_key,
    size_t expected_len,
    char *err_buf,
    size_t err_len
) {
    @autoreleasepool {
        if (account == NULL || out_key == NULL || expected_len == 0) {
            copy_message(@"invalid keychain parameters", err_buf, err_len);
            return 2;
        }
        NSString *nsAccount = [NSString stringWithUTF8String:account];
        if (nsAccount == nil) {
            copy_message(@"invalid keychain account string", err_buf, err_len);
            return 2;
        }

        NSDictionary *query = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService: kSiloKeychainService,
            (__bridge id)kSecAttrAccount: nsAccount,
            (__bridge id)kSecReturnData: @YES,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
        };
        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        if (status == errSecItemNotFound) {
            return 1;
        }
        if (status != errSecSuccess) {
            copy_osstatus(status, err_buf, err_len);
            return 2;
        }
        NSData *data = CFBridgingRelease(result);
        if (![data isKindOfClass:[NSData class]] || data.length != expected_len) {
            copy_message(@"unexpected key length in Keychain", err_buf, err_len);
            return 2;
        }
        memcpy(out_key, data.bytes, expected_len);
        return 0;
    }
}

/*
 * Return codes:
 *   0 = ok (or already absent)
 *   2 = error
 */
int silo_keychain_delete(const char *account, char *err_buf, size_t err_len) {
    @autoreleasepool {
        if (account == NULL) {
            return 0;
        }
        NSString *nsAccount = [NSString stringWithUTF8String:account];
        if (nsAccount == nil) {
            return 0;
        }
        NSDictionary *query = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService: kSiloKeychainService,
            (__bridge id)kSecAttrAccount: nsAccount,
        };
        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
        if (status != errSecSuccess && status != errSecItemNotFound) {
            copy_osstatus(status, err_buf, err_len);
            return 2;
        }
        return 0;
    }
}
