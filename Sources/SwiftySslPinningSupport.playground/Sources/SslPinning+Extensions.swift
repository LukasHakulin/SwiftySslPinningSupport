import Foundation
import Security
import CommonCrypto

public extension SecCertificate {

    /**
     * Loads a Certificate from a DER (binary) encoded file. Wraps `SecCertificateCreateWithData`.
     *
     * - parameter url: Url to the DER encoded file from which to load the Certificate
     * - returns: A `SecCertificate` if it could be loaded, or `nil`
     */
    static func loadCertificate(fromUrl url: URL) -> SecCertificate? {
        guard
            let data = try? Data(contentsOf: url) as CFData,
            let certificate = SecCertificateCreateWithData(nil, data)
        else { return nil }

        return certificate
    }

    /**
     * Returns the data of the Certificate by calling `SecCertificateCopyData`.
     *
     * - returns: the data of the Certificate
     */
    var data: Data {
        return SecCertificateCopyData(self) as Data
    }

    /**
     * Tries to return the Public Key of this certificate. Wraps `SecTrustCopyPublicKey`.
     * Uses `SecTrustCreateWithCertificates` with `SecPolicyCreateBasicX509()` policy.
     *
     * - returns: the Public Key if possible
     */
    var publicKey: SecKey? {
        let policy: SecPolicy = SecPolicyCreateBasicX509()
        var uTrust: SecTrust?
        let resultCode = SecTrustCreateWithCertificates([self] as CFArray, policy, &uTrust)
        guard
            resultCode == errSecSuccess,
            let trust = uTrust
        else { return nil }

        return SecTrustCopyKey(trust)
    }

}

public extension SecKey {

    /**
     * Returns the data representation of the Public Key by calling `SecKeyCopyExternalRepresentation`.
     *
     * - returns: the data representation of the Public Key
     */
    var data: Data? {
        return SecKeyCopyExternalRepresentation(self, nil) as Data?
    }
}

public extension Data {

    /**
     * Returns the HEX encoded string representation of Data.
     *
     * - returns: the HEX encoded string representation of Data
     */
    var hexEncodedString: String {
        return map { String(format: "%02hhx", $0) }.joined()
    }

    /**
     * Returns the data hash representation of Data by SHA-2 - digest 256 bits standard.
     *
     * - returns: the data hash representation of Data by SHA-2 - digest 256 bits standard
     */
    var sha256: Data {
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        self.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(self.count), &hash) }

        return Data(hash)
    }
}
