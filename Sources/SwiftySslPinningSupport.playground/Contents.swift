import Foundation
import CommonCrypto

/**
 * Cause `SecCertificateCreateWithData` input is defined as `A DER (Distinguished Encoding Rules) representation of an X.509 certificate.`
 *  is necessary to use certificates in binary format. (https://developer.apple.com/documentation/security/1396073-seccertificatecreatewithdata)
 *  To convert certificate in base64 form to binary use in console: `openssl x509 -in certificate.crt -out certificate.der -outform DER`
 */

let publicKeysHashes = ["binary format/developer.apple.com", "binary format/www.google.com"]
    .map { Bundle.main.url(forResource: $0, withExtension: "der") }
    .compactMap { $0 }
    .map { SecCertificate.loadCertificate(fromUrl: $0) }
    .compactMap { $0 }
    .map { $0.publicKey }
    .compactMap { $0 }
    .map { $0.data }
    .compactMap { $0 }
    .map { $0.sha256 }


// Print all key hash from certificates

// HEX format
print("\nHEX encoded keys")
publicKeysHashes
    .map { $0.hexEncodedString }
    .forEach { print($0) }

// Base64 format
print("\nBase64 encoded keys")
publicKeysHashes
    .map { $0.base64EncodedString() }
    .forEach { print($0) }
