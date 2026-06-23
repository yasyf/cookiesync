// Secure-Enclave key-wrapper for the daemon's short-TTL AES key cache.
//
// The daemon keeps a derived Safe Storage key in memory only for a brief TTL, but
// the AT-REST cache bytes must be useless off-box: a leaked blob or a core dump
// must not yield a usable key. Each cache entry is therefore wrapped with a
// per-boot EPHEMERAL Secure-Enclave P-256 key whose private half never leaves the
// Enclave. ECIES (cofactor X9.63 SHA-256 AES-GCM) gives authenticated encryption to
// that public key; only the live SE key can decrypt. The presence gate (Touch ID)
// already happened upstream in keyvault.swift, so this key carries NO biometry —
// just .privateKeyUsage and accessible-when-unlocked-this-device-only.
//
// Subcommands dispatch on argv[1] (each takes a <label>):
//   newkey  <label>   delete stale cookiesync-cache keys, then create the SE key
//   wrap    <label>   stdin plaintext -> stdout ECIES blob
//   unwrap  <label>   stdin blob -> stdout plaintext
//   dropkey <label>   delete the SE key
//
// Exit codes:
//   0 = ok
//   1 = operation failed (key missing, decrypt failed, bad input)
//   2 = unavailable (no Secure Enclave, key generation refused)

import Foundation
import Security

let CACHE_TAG_PREFIX = "cookiesync.cache."

func fail(_ message: String) {
    FileHandle.standardError.write(Data("keycache: \(message)\n".utf8))
}

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
    ] as CFDictionary)
}

func loadPrivateKey(_ label: String) -> SecKey? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrApplicationTag as String: applicationTag(label),
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecReturnRef as String: true,
    ]
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
        return nil
    }
    return (item as! SecKey)
}

func newkey(_ label: String) -> Int32 {
    deleteStaleCacheKeys()

    var acError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .privateKeyUsage,
        &acError
    ) else {
        fail("could not build access control: \(acError?.takeRetainedValue().localizedDescription ?? "unknown")")
        return 2
    }
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: applicationTag(label),
            kSecAttrAccessControl as String: access,
        ],
    ]
    var genError: Unmanaged<CFError>?
    guard SecKeyCreateRandomKey(attributes as CFDictionary, &genError) != nil else {
        fail("SecKeyCreateRandomKey failed: \(genError?.takeRetainedValue().localizedDescription ?? "unknown")")
        return 2
    }
    return 0
}

func wrap(_ label: String) -> Int32 {
    guard let privateKey = loadPrivateKey(label) else {
        fail("no Secure-Enclave cache key for '\(label)'")
        return 1
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
        fail("SecKeyCreateEncryptedData failed: \(encError?.takeRetainedValue().localizedDescription ?? "unknown")")
        return 1
    }
    FileHandle.standardOutput.write(blob as Data)
    return 0
}

func unwrap(_ label: String) -> Int32 {
    guard let privateKey = loadPrivateKey(label) else {
        fail("no Secure-Enclave cache key for '\(label)'")
        return 1
    }
    let blob = FileHandle.standardInput.readDataToEndOfFile()
    var decError: Unmanaged<CFError>?
    guard let plaintext = SecKeyCreateDecryptedData(
        privateKey,
        .eciesEncryptionCofactorX963SHA256AESGCM,
        blob as CFData,
        &decError
    ) else {
        fail("SecKeyCreateDecryptedData failed: \(decError?.takeRetainedValue().localizedDescription ?? "unknown")")
        return 1
    }
    FileHandle.standardOutput.write(plaintext as Data)
    return 0
}

func dropkey(_ label: String) -> Int32 {
    SecItemDelete([
        kSecClass as String: kSecClassKey,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrApplicationTag as String: applicationTag(label),
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    ] as CFDictionary)
    return 0
}

let arguments = CommandLine.arguments
guard arguments.count >= 3 else {
    fail("usage: keycache <newkey|wrap|unwrap|dropkey> <label>")
    exit(1)
}

switch arguments[1] {
case "newkey":
    exit(newkey(arguments[2]))
case "wrap":
    exit(wrap(arguments[2]))
case "unwrap":
    exit(unwrap(arguments[2]))
case "dropkey":
    exit(dropkey(arguments[2]))
default:
    fail("unknown subcommand '\(arguments[1])'")
    exit(1)
}
