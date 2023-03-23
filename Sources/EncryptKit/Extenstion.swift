//
//  Extenstion.swift
//  EncryptKit
//
//  Created by Amir Mohammadi on 1/3/1402 AP.
//

import Foundation

public extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

public extension String {
    func hexDecodedData() -> Data? {
        var data = Data(capacity: count / 2)
        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: self, options: [], range: NSRange(self.startIndex..., in: self)) { match, _, _ in
            if let match = match {
                let byteStringRange = Range(match.range, in: self)!
                let byteString = self[byteStringRange]
                if let num = UInt8(byteString, radix: 16) {
                    data.append(num)
                }
            }
        }
        guard data.count > 0 else { return nil }
        return data
    }
}
