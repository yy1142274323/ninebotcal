import Foundation
import CryptoKit
import CommonCrypto

extension Data {
    init(hex: String) {
        var s = hex.replacingOccurrences(of: " ", with: "")
        if s.count % 2 != 0 { s = "0" + s }
        var out = [UInt8]()
        out.reserveCapacity(s.count / 2)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            if let b = UInt8(s[idx..<next], radix: 16) { out.append(b) }
            idx = next
        }
        self = Data(out)
    }

    var hexString: String { map { String(format: "%02x", $0) }.joined() }
    var hexUpper: String { map { String(format: "%02X", $0) }.joined() }
    var bytes: [UInt8] { Array(self) }
}

enum NSha1 {
    static func digest(_ parts: [Data]) -> Data {
        var hasher = Insecure.SHA1()
        for p in parts { hasher.update(data: p) }
        return Data(hasher.finalize())
    }
}

enum NAES {
    /// AES-128 ECB, single 16-byte block (the protocol only ever needs one block at a time).
    static func ecbEncryptBlock(key: Data, block: Data) -> Data {
        precondition(key.count == 16, "AES-128 key must be 16 bytes")
        precondition(block.count == 16, "block must be 16 bytes")
        var out = [UInt8](repeating: 0, count: 16)
        var outLen = 0
        let status = key.withUnsafeBytes { keyPtr -> CCCryptorStatus in
            block.withUnsafeBytes { dataPtr -> CCCryptorStatus in
                CCCrypt(CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyPtr.baseAddress, key.count,
                        nil,
                        dataPtr.baseAddress, block.count,
                        &out, out.count, &outLen)
            }
        }
        guard status == kCCSuccess, outLen == 16 else {
            return Data(repeating: 0, count: 16)
        }
        return Data(out)
    }
}
