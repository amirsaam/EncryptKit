//
//  EncryptKit.swift
//  EncryptKit
//
//  Created by Amir Mohammadi on 1/3/1402 AP.
//

import Foundation
import CommonCrypto

/// Orginal Idea is from a friend of mine, Amachik: https://github.com/Amachik/EncryptKit
public final class EncryptKit {
    public let stringToEncrypt: String

    public init(stringToEncrypt: String) {
        self.stringToEncrypt = stringToEncrypt
    }

    //
    public func doReturnEncrypted() -> (encryptedId: String, keyHex: String, ivHex: String)? {
        var encreyptedData = Data()
        var key = Data(count: kCCKeySizeAES256)
        var iv = Data(count: kCCBlockSizeAES128)
        DispatchQueue(label: "keyQueue").sync {
            _ = key.withUnsafeMutableBytes { keyBytes in
                SecRandomCopyBytes(kSecRandomDefault, keyBytes.count, keyBytes.baseAddress!)
            }
            _ = iv.withUnsafeMutableBytes { ivBytes in
                SecRandomCopyBytes(kSecRandomDefault, ivBytes.count, ivBytes.baseAddress!)
            }
        }
        guard let concatenatedData = stringToEncrypt.data(using: .utf8) else { return nil }
        DispatchQueue(label: "dataQueue").sync {
            encreyptedData = encryptAES256(data: concatenatedData, key: key, iv: iv)!
        }
        return (encreyptedData.hexEncodedString(), key.hexEncodedString(), iv.hexEncodedString())
    }

    //
    public func doReturnDecrypted(encryptedId: String, keyHex: String, ivHex: String) -> String? {
        guard let encryptedData = encryptedId.hexDecodedData(),
              let key = keyHex.hexDecodedData(),
              let iv = ivHex.hexDecodedData() else { return nil }
        let decryptedData = decryptAES256(data: encryptedData, key: key, iv: iv)!
        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else { return nil }
        return decryptedString
    }

    //
    private func encryptAES256(data: Data, key: Data, iv: Data) -> Data? {
        let cryptLength = data.count + kCCBlockSizeAES128
        var cryptData = Data(count: cryptLength)

        let keyLength = kCCKeySizeAES256
        let options = CCOptions(kCCOptionPKCS7Padding)

        var bytesLength = 0

        let status = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(CCOperation(kCCEncrypt),
                                CCAlgorithm(kCCAlgorithmAES),
                                options,
                                keyBytes.baseAddress, keyLength,
                                ivBytes.baseAddress,
                                dataBytes.baseAddress, data.count,
                                cryptBytes.baseAddress, cryptLength,
                                &bytesLength)
                    }
                }
            }
        }

        if status != kCCSuccess {
            return nil
        }

        cryptData.count = bytesLength
        return cryptData
    }

    //
    private func decryptAES256(data: Data, key: Data, iv: Data) -> Data? {
        let cryptLength = data.count + kCCBlockSizeAES128
        var cryptData = Data(count: cryptLength)

        let keyLength = kCCKeySizeAES256
        let options = CCOptions(kCCOptionPKCS7Padding)

        var bytesLength = 0

        let status = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(CCOperation(kCCDecrypt),
                                CCAlgorithm(kCCAlgorithmAES),
                                options,
                                keyBytes.baseAddress, keyLength,
                                ivBytes.baseAddress,
                                dataBytes.baseAddress, data.count,
                                cryptBytes.baseAddress, cryptLength,
                                &bytesLength)
                    }
                }
            }
        }

        if status != kCCSuccess {
            return nil
        }
        cryptData.count = bytesLength
        return cryptData
    }

}
