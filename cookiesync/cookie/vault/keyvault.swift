// Secure-Enclave-bound key vault for cookiesync.
//
// Unlike a cosmetic LAContext gate in front of a sticky "Always Allow"
// /usr/bin/security read, this stores the Safe Storage password in a NEW
// data-protection keychain item whose access control is bound to
// biometry-or-passcode. Every retrieve forces a real biometric/passcode
// evaluation through the keychain itself — there is no "Always Allow" to make
// the read silent.
//
// Subcommands dispatch on argv[1]:
//   enroll <vault-service> <safe-storage-service>
//   retrieve <vault-service>
//   status <vault-service>
//
// Exit codes:
//   0 = ok
//   1 = cancelled / denied
//   2 = unavailable (no biometrics + no passcode, non-interactive, or not found)

import Foundation
import LocalAuthentication
import Security

func fail(_ message: String) {
    FileHandle.standardError.write(Data("keyvault: \(message)\n".utf8))
}

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

func enroll(vaultService: String, safeStorageService: String) -> Int32 {
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
        kSecUseDataProtectionKeychain as String: true,
    ] as CFDictionary)
    let add: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: vaultService,
        kSecValueData as String: password,
        kSecAttrAccessControl as String: access,
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

func retrieve(vaultService: String) -> Int32 {
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

func status(vaultService: String) -> Int32 {
    let context = LAContext()
    var policyError: NSError?
    let biometry = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    let deviceAuth = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &policyError)
    let exists = SecItemCopyMatching([
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: vaultService,
        kSecUseDataProtectionKeychain as String: true,
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ] as CFDictionary, nil) == errSecSuccess
    let report = "biometry=\(biometry) passcode=\(deviceAuth) vault=\(exists)"
    FileHandle.standardOutput.write(Data("\(report)\n".utf8))
    guard deviceAuth else { return 2 }
    return exists ? 0 : 2
}

let arguments = CommandLine.arguments
guard arguments.count >= 3 else {
    fail("usage: keyvault <enroll|retrieve|status> <vault-service> [safe-storage-service]")
    exit(2)
}

switch arguments[1] {
case "enroll":
    guard arguments.count >= 4 else {
        fail("enroll requires <vault-service> <safe-storage-service>")
        exit(2)
    }
    exit(enroll(vaultService: arguments[2], safeStorageService: arguments[3]))
case "retrieve":
    exit(retrieve(vaultService: arguments[2]))
case "status":
    exit(status(vaultService: arguments[2]))
default:
    fail("unknown subcommand '\(arguments[1])'")
    exit(2)
}
