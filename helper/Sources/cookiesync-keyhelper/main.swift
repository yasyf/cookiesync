// cookiesync-keyhelper — one Developer-ID-signable binary that merges the two
// runtime-compiled Swift helpers (the consent key vault + the Secure-Enclave key
// cache) behind argv[1].
//
// Why one signed .app instead of two ad-hoc binaries: macOS 15/26 SIGKILL an
// ad-hoc (Team-less) signature at exec, and a Secure-Enclave key generation under
// an ad-hoc signature is refused. A Developer ID signature with an embedded
// provisioning profile and a keychain-access-groups entitlement clears the AMFI
// kill and authorizes the SE keys + vault items in the app's keychain group.
//
// All keychain items (the biometry-bound vault password and the per-boot SE cache
// key) carry kSecAttrAccessGroup = the app's keychain-access-group, so the
// provisioning profile authorizes them.
//
// Subcommands dispatch on argv[1]:
//
//   Consent vault (biometry-or-passcode-bound Safe Storage password):
//     vault-enroll   <vault-service> <safe-storage-service>
//     vault-retrieve <vault-service>
//     vault-status   <vault-service>
//
//   Secure-Enclave cache (per-boot ephemeral P-256 ECIES wrapper):
//     cache-newkey   <label>   delete stale cache keys, then create the SE key
//     cache-wrap     <label>   stdin plaintext  -> stdout ECIES blob
//     cache-unwrap   <label>   stdin blob       -> stdout plaintext
//     cache-dropkey  <label>   delete the SE key
//
// Exit codes (shared across both families):
//   0 = ok
//   1 = cancelled / denied / operation failed (key missing, decrypt failed, bad input)
//   2 = unavailable (no biometrics + no passcode, no Secure Enclave, not found,
//       non-interactive, key generation misconfigured)
//   3 = presence unavailable: the data-protection keybag refused the operation with
//       errSecInteractionNotAllowed (-25308) — screen locked / no user present;
//       retry after unlock

import Foundation
import LocalAuthentication
import Security

let KEYCHAIN_ACCESS_GROUP = "SXKCTF23Q2.com.yasyf.cookiesync.helper"
let CACHE_TAG_PREFIX = "cookiesync.cache."

func fail(_ message: String) {
    FileHandle.standardError.write(Data("keyhelper: \(message)\n".utf8))
}

// failSec reports a failed Security call to stderr (operation + description + numeric
// OSStatus) and classifies it: errSecInteractionNotAllowed (-25308) means the
// data-protection keybag refused the call because no user is present (locked screen)
// and exits 3; anything else exits `otherwise`.
func failSec(_ operation: String, _ error: Unmanaged<CFError>?, otherwise: Int32) -> Int32 {
    let nsError = error!.takeRetainedValue() as Error as NSError
    fail("\(operation) failed: \(nsError.localizedDescription) (OSStatus \(nsError.code))")
    if nsError.domain == NSOSStatusErrorDomain, nsError.code == Int(errSecInteractionNotAllowed) {
        return 3
    }
    return otherwise
}

// MARK: - Consent vault (was keyvault.swift)

func readSafeStorage(_ service: String) -> Data? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
          let data = item as? Data else {
        return nil
    }
    return data
}

func vaultEnroll(vaultService: String, safeStorageService: String) -> Int32 {
    guard let password = readSafeStorage(safeStorageService) else {
        fail("could not read '\(safeStorageService)' from the login keychain")
        return 2
    }
    var acError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.biometryCurrentSet, .or, .devicePasscode],
        &acError
    ) else {
        fail("could not build access control: \(acError?.takeRetainedValue().localizedDescription ?? "unknown")")
        return 2
    }
    SecItemDelete([
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: vaultService,
        kSecAttrAccessGroup as String: KEYCHAIN_ACCESS_GROUP,
        kSecUseDataProtectionKeychain as String: true,
    ] as CFDictionary)
    let add: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: vaultService,
        kSecValueData as String: password,
        kSecAttrAccessControl as String: access,
        kSecAttrAccessGroup as String: KEYCHAIN_ACCESS_GROUP,
        kSecUseDataProtectionKeychain as String: true,
        kSecAttrSynchronizable as String: false,
    ]
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else {
        fail("SecItemAdd failed: \(SecCopyErrorMessageString(status, nil) as String? ?? "\(status)")")
        return 1
    }
    return 0
}

func vaultRetrieve(vaultService: String) -> Int32 {
    let context = LAContext()
    var policyError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &policyError) else {
        fail("unavailable: \(policyError?.localizedDescription ?? "no biometrics or passcode")")
        return 2
    }
    let reason = ProcessInfo.processInfo.environment["COOKIESYNC_TOUCHID_REASON"]
        ?? "unlock your cookie vault"

    let semaphore = DispatchSemaphore(value: 0)
    var approved = false
    var evalError: Error?
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, error in
        approved = ok
        evalError = error
        semaphore.signal()
    }
    semaphore.wait()

    guard approved else {
        if let laError = evalError as? LAError {
            switch laError.code {
            case .notInteractive, .invalidContext, .biometryNotAvailable, .passcodeNotSet:
                return 2
            default:
                return 1
            }
        }
        return 1
    }

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: vaultService,
        kSecAttrAccessGroup as String: KEYCHAIN_ACCESS_GROUP,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecUseDataProtectionKeychain as String: true,
        kSecUseAuthenticationContext as String: context,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    switch status {
    case errSecSuccess:
        guard let data = item as? Data else {
            fail("vault item returned no data")
            return 1
        }
        FileHandle.standardOutput.write(data)
        return 0
    case errSecItemNotFound, errSecAuthFailed:
        // The biometry-bound item is gone or invalidated (the fingerprint set
        // changed, which voids a .biometryCurrentSet ACL). Signal re-enroll.
        fail("vault item '\(vaultService)' missing or invalidated: re-enroll")
        return 2
    case errSecUserCanceled:
        fail("retrieve cancelled by user")
        return 1
    default:
        fail("SecItemCopyMatching failed: \(SecCopyErrorMessageString(status, nil) as String? ?? "\(status)")")
        return 1
    }
}

func vaultStatus(vaultService: String) -> Int32 {
    let context = LAContext()
    var policyError: NSError?
    let biometry = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    let deviceAuth = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &policyError)
    let exists = SecItemCopyMatching([
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: vaultService,
        kSecAttrAccessGroup as String: KEYCHAIN_ACCESS_GROUP,
        kSecUseDataProtectionKeychain as String: true,
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ] as CFDictionary, nil) == errSecSuccess
    let report = "biometry=\(biometry) passcode=\(deviceAuth) vault=\(exists)"
    FileHandle.standardOutput.write(Data("\(report)\n".utf8))
    guard deviceAuth else { return 2 }
    return exists ? 0 : 2
}

// MARK: - Secure-Enclave cache (was keycache.swift)

func applicationTag(_ label: String) -> Data {
    Data("\(CACHE_TAG_PREFIX)\(label)".utf8)
}

func deleteStaleCacheKeys() {
    // A fresh per-boot key means any prior cookiesync-cache SE key is dead weight
    // whose ciphertext is unrecoverable; sweep the whole tag namespace.
    SecItemDelete([
        kSecClass as String: kSecClassKey,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecAttrAccessGroup as String: KEYCHAIN_ACCESS_GROUP,
        kSecUseDataProtectionKeychain as String: true,
    ] as CFDictionary)
}

func loadPrivateKey(_ label: String) -> (key: SecKey?, status: OSStatus) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrApplicationTag as String: applicationTag(label),
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecAttrAccessGroup as String: KEYCHAIN_ACCESS_GROUP,
        kSecUseDataProtectionKeychain as String: true,
        kSecReturnRef as String: true,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess else {
        return (nil, status)
    }
    return ((item as! SecKey), errSecSuccess)
}

// failKeyLookup classifies a failed SE cache-key lookup: the key is created under
// kSecAttrAccessibleWhenUnlockedThisDeviceOnly, so a locked keybag refuses the item
// lookup itself with errSecInteractionNotAllowed (-25308) — that exits 3, like
// failSec. errSecItemNotFound is the documented exit-1 "no key" path; anything else
// exits 1 (operation failed).
func failKeyLookup(_ label: String, _ status: OSStatus) -> Int32 {
    if status == errSecItemNotFound {
        fail("no Secure-Enclave cache key for '\(label)'")
        return 1
    }
    fail("SecItemCopyMatching failed: \(SecCopyErrorMessageString(status, nil) as String? ?? "\(status)") (OSStatus \(status))")
    if status == errSecInteractionNotAllowed {
        return 3
    }
    return 1
}

func cacheNewkey(_ label: String) -> Int32 {
    deleteStaleCacheKeys()

    var acError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .privateKeyUsage,
        &acError
    ) else {
        return failSec("SecAccessControlCreateWithFlags", acError, otherwise: 2)
    }
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecUseDataProtectionKeychain as String: true,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: applicationTag(label),
            kSecAttrAccessGroup as String: KEYCHAIN_ACCESS_GROUP,
            kSecAttrAccessControl as String: access,
        ],
    ]
    var genError: Unmanaged<CFError>?
    guard SecKeyCreateRandomKey(attributes as CFDictionary, &genError) != nil else {
        return failSec("SecKeyCreateRandomKey", genError, otherwise: 2)
    }
    return 0
}

func cacheWrap(_ label: String) -> Int32 {
    let (loaded, status) = loadPrivateKey(label)
    guard let privateKey = loaded else {
        return failKeyLookup(label, status)
    }
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
        fail("could not derive public key for '\(label)'")
        return 1
    }
    let plaintext = FileHandle.standardInput.readDataToEndOfFile()
    var encError: Unmanaged<CFError>?
    guard let blob = SecKeyCreateEncryptedData(
        publicKey,
        .eciesEncryptionCofactorX963SHA256AESGCM,
        plaintext as CFData,
        &encError
    ) else {
        return failSec("SecKeyCreateEncryptedData", encError, otherwise: 1)
    }
    FileHandle.standardOutput.write(blob as Data)
    return 0
}

func cacheUnwrap(_ label: String) -> Int32 {
    let (loaded, status) = loadPrivateKey(label)
    guard let privateKey = loaded else {
        return failKeyLookup(label, status)
    }
    let blob = FileHandle.standardInput.readDataToEndOfFile()
    var decError: Unmanaged<CFError>?
    guard let plaintext = SecKeyCreateDecryptedData(
        privateKey,
        .eciesEncryptionCofactorX963SHA256AESGCM,
        blob as CFData,
        &decError
    ) else {
        return failSec("SecKeyCreateDecryptedData", decError, otherwise: 1)
    }
    FileHandle.standardOutput.write(plaintext as Data)
    return 0
}

func cacheDropkey(_ label: String) -> Int32 {
    SecItemDelete([
        kSecClass as String: kSecClassKey,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrApplicationTag as String: applicationTag(label),
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecAttrAccessGroup as String: KEYCHAIN_ACCESS_GROUP,
        kSecUseDataProtectionKeychain as String: true,
    ] as CFDictionary)
    return 0
}

// MARK: - Dispatch

let arguments = CommandLine.arguments
guard arguments.count >= 3 else {
    fail("usage: cookiesync-keyhelper <subcommand> <arg> [arg]")
    fail("  vault-enroll <vault-service> <safe-storage-service>")
    fail("  vault-retrieve <vault-service>")
    fail("  vault-status <vault-service>")
    fail("  cache-newkey|cache-wrap|cache-unwrap|cache-dropkey <label>")
    exit(2)
}

switch arguments[1] {
case "vault-enroll":
    guard arguments.count >= 4 else {
        fail("vault-enroll requires <vault-service> <safe-storage-service>")
        exit(2)
    }
    exit(vaultEnroll(vaultService: arguments[2], safeStorageService: arguments[3]))
case "vault-retrieve":
    exit(vaultRetrieve(vaultService: arguments[2]))
case "vault-status":
    exit(vaultStatus(vaultService: arguments[2]))
case "cache-newkey":
    exit(cacheNewkey(arguments[2]))
case "cache-wrap":
    exit(cacheWrap(arguments[2]))
case "cache-unwrap":
    exit(cacheUnwrap(arguments[2]))
case "cache-dropkey":
    exit(cacheDropkey(arguments[2]))
default:
    fail("unknown subcommand '\(arguments[1])'")
    exit(2)
}
