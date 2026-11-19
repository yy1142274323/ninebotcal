import Foundation

/// 九号 legacy UART-over-BLE 协议，还原自 BFG电量校准 5.0.35 (classes u2.o / u2.h / u2.i)
enum NB {

    // MARK: - 常量

    static let key0 = Data(hex: "97CFB802844143DE56002B3B34780A5D")

    static let svcUART  = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
    static let charTX   = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"   // 手机 -> 车
    static let charRX   = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"   // 车 -> 手机 (notify)
    static let cccd     = "00002902-0000-1000-8000-00805f9b34fb"

    static let srcPhone: UInt8 = 0x3E
    static let dstMain:  UInt8 = 0x01
    static let dstMeter: UInt8 = 0x09
    static let dstDIS:   UInt8 = 0x10

    static let cmdRead:  UInt8 = 0x01
    static let cmdWrite: UInt8 = 0x02
    static let cmdAck:   UInt8 = 0x04
    static let cmdPreComm: UInt8 = 0x5B
    static let cmdAuth:  UInt8 = 0x5D

    static let preComm = Data(hex: "5AA5003E045B00")

    // MARK: - 寄存器

    struct Register {
        let key: String
        let dst: UInt8
        let reg: UInt8
        let len: Int
        let title: String
        let unit: String
    }

    static let registers: [Register] = [
        Register(key: "dis_soc",      dst: dstDIS,   reg: 0x00, len: 1, title: "仪表电量",   unit: "%"),
        Register(key: "dis_misc",     dst: dstDIS,   reg: 0x02, len: 1, title: "仪表状态",   unit: ""),
        Register(key: "dis_profile",  dst: dstDIS,   reg: 0x92, len: 2, title: "仪表配置档位", unit: ""),
        Register(key: "dis_capacity", dst: dstDIS,   reg: 0x1C, len: 2, title: "仪表容量",   unit: "mAh"),
        Register(key: "dash_version", dst: dstMain,  reg: 0x1A, len: 2, title: "仪表版本",   unit: ""),
        Register(key: "e1",           dst: dstMain,  reg: 0x1E, len: 2, title: "0x1E",      unit: ""),
        Register(key: "bfg_version",  dst: dstMain,  reg: 0x3D, len: 2, title: "BFG 版本",  unit: ""),
        Register(key: "vrla_voltage", dst: dstMain,  reg: 0xB1, len: 2, title: "铅酸电压",  unit: "0.1V"),
        Register(key: "battery",      dst: dstMain,  reg: 0xB5, len: 2, title: "电池电压",  unit: "0.1V"),
        Register(key: "d1",           dst: dstMain,  reg: 0xD1, len: 2, title: "0xD1",      unit: ""),
        Register(key: "reg44",        dst: dstMain,  reg: 0x44, len: 2, title: "0x44",      unit: ""),
        Register(key: "meter_ver",    dst: dstMeter, reg: 0x02, len: 2, title: "计量模块版本", unit: ""),
    ]

    static func register(_ key: String) -> Register? { registers.first { $0.key == key } }

    // MARK: - 容量槽位 / 电压编码

    /// 仪表配置字节高半字节 -> 容量 (mAh)，来自 dex 静态表 u2.i;->a
    static let capacitySlots: [Int] = [
        20000, 10500, 18000, 36000, 10500, 26000, 14000, 38000,
        13000, 22000, 39000, 45000, 46000, 55000, 52000, 18000,
    ]

    /// 低半字节 -> 电压
    static let voltDecode: [UInt8: Int] = [1: 72, 2: 60, 3: 48, 0: 72]
    static let voltEncode: [Int: UInt8] = [72: 1, 60: 2, 48: 3]

    static func profileVoltage(_ p: UInt8) -> Int? { voltDecode[p & 0x0F] }
    static func profileCapacity(_ p: UInt8) -> Int { capacitySlots[Int((p >> 4) & 0x0F)] }
    static func profileSlot(_ p: UInt8) -> Int { Int((p >> 4) & 0x0F) }

    static func makeProfile(current: UInt8, voltage: Int, capacityIndex: Int?) throws -> UInt8 {
        guard let code = voltEncode[voltage] else {
            throw NBError.invalidArgument("不支持的电压档位 \(voltage)V")
        }
        let hi: UInt8 = capacityIndex.map { UInt8($0 & 0x0F) } ?? ((current >> 4) & 0x0F)
        return ((hi << 4) | code) & 0xFF
    }

    // MARK: - 帧构造

    static func frame(dst: UInt8, cmd: UInt8, reg: UInt8, data: Data = Data()) -> Data {
        var d = Data([0x5A, 0xA5, UInt8(data.count), srcPhone, dst, cmd, reg])
        d.append(data)
        return d
    }

    static func readFrame(_ r: Register) -> Data {
        frame(dst: r.dst, cmd: cmdRead, reg: r.reg, data: Data([UInt8(r.len)]))
    }

    static func authFrame(sn: Data) throws -> Data {
        guard sn.count == 14 else { throw NBError.invalidArgument("SN 必须 14 字节") }
        var d = Data(hex: "5AA50E3E045D00")
        d.append(sn)
        return d
    }

    /// 仪表盘档位写入：5A A5 02 3E 01 02 92 <profile> 00
    static func disWriteFrame(profile: UInt8) -> Data {
        frame(dst: dstMain, cmd: cmdWrite, reg: 0x92, data: Data([profile, 0x00]))
    }

    // MARK: - 帧解析

    struct Frame {
        let raw: Data
        var len: Int { Int(raw[2]) }
        var src: UInt8 { raw[3] }
        var dst: UInt8 { raw[4] }
        var cmd: UInt8 { raw[5] }
        var reg: UInt8 { raw[6] }
        var payload: Data { raw.count >= 7 + len ? raw.subdata(in: 7..<(7 + len)) : Data() }

        var le16: Int { payload.count >= 2 ? Int(payload[0]) | (Int(payload[1]) << 8) : -1 }
        var le8: Int { payload.count >= 1 ? Int(payload[0]) : -1 }
    }

    static func parse(_ d: Data) throws -> Frame {
        guard d.count >= 7 else { throw NBError.protocolError("帧过短(\(d.count))") }
        guard d[0] == 0x5A, d[1] == 0xA5 else {
            throw NBError.protocolError("帧头错误 \(d[0..<2].map { String(format: "%02X", $0) }.joined())")
        }
        let f = Frame(raw: d)
        guard 7 + f.len <= d.count else { throw NBError.protocolError("帧长度字段与数据不符") }
        return f
    }

    /// 同一个 key 的 6 种字节化方式（探针逐个试）
    static func passwordVariants(_ key: String) -> [(String, Data)] {
        var out: [(String, Data)] = []
        let ascii = Array(key.data(using: .ascii) ?? Data())

        func pad(_ a: [UInt8], left: Bool) -> Data {
            var b = Array(a.prefix(16))
            let fill = Array(repeating: UInt8(0), count: max(0, 16 - b.count))
            b = left ? fill + b : b + fill
            return Data(b.prefix(16))
        }

        out.append(("ASCII 右补零", pad(ascii, left: false)))
        out.append(("ASCII 左补零", pad(ascii, left: true)))

        if let n = UInt32(key) {
            let le = withUnsafeBytes(of: n.littleEndian) { Array($0) }
            let be = withUnsafeBytes(of: n.bigEndian) { Array($0) }
            out.append(("u32 小端", pad(le, left: false)))
            out.append(("u32 大端", pad(be, left: false)))
            out.append(("hex 字符串", pad(Array(String(format: "%04x", n).utf8), left: false)))
            if let d = UInt64(key) {
                let le8 = withUnsafeBytes(of: d.littleEndian) { Array($0) }
                out.append(("u64 小端", pad(le8, left: false)))
            }
        }
        return out
    }
    static func le16(_ d: Data) -> Int { d.count >= 2 ? Int(d[0]) | (Int(d[1]) << 8) : -1 }
}

enum NBError: LocalizedError {
    case invalidArgument(String)
    case protocolError(String)
    case timeout(String)
    case notConnected
    case handshake(String)
    case crypto(String)

    var errorDescription: String? {
        switch self {
        case .invalidArgument(let s): return s
        case .protocolError(let s): return "协议错误：\(s)"
        case .timeout(let s): return "超时：\(s)"
        case .notConnected: return "未连接车辆"
        case .handshake(let s): return "握手失败：\(s)"
        case .crypto(let s): return "加密错误：\(s)"
        }
    }
}

/// Enc1(预认证) / Enc2(会话) 封装，与 u2.o 完全一致
final class NBCipher {

    private let pwd16: Data
    private let key1: Data
    private let pad1: Data

    private(set) var authParam: Data?
    private(set) var key2: Data?

    convenience init(password: String) {
        var bytes = Array(password.data(using: .ascii) ?? Data())
        if bytes.count > 16 { bytes = Array(bytes.prefix(16)) }
        while bytes.count < 16 { bytes.append(0) }
        self.init(pwd16: Data(bytes))
    }

    /// 直接给 16 字节密钥材料（探针会试不同编码）
    init(pwd16: Data) {
        var b = Data(pwd16.prefix(16))
        if b.count < 16 { b.append(Data(count: 16 - b.count)) }
        self.pwd16 = b
        key1 = NSha1.digest([b, NB.key0]).prefix(16)
        pad1 = NAES.ecbEncryptBlock(key: key1, block: NB.key0)
    }

    // MARK: Enc1

    func encryptEnc1(_ plain: Data) -> Data {
        precondition(plain.count >= 3)
        let payload = plain.subdata(in: 3..<plain.count)
        var ct = Data(capacity: payload.count)
        for (i, b) in payload.enumerated() { ct.append(b ^ pad1[i & 15]) }
        let sum = payload.reduce(0) { ($0 &+ Int($1)) & 0xFFFF }
        let cs = (~sum) & 0xFFFF
        var out = plain.prefix(3)
        out.append(ct)
        out.append(contentsOf: [0x00, 0x00, UInt8(cs & 0xFF), UInt8((cs >> 8) & 0xFF), 0x00, 0x00])
        return out
    }

    func decryptEnc1(_ framed: Data) -> Data {
        guard framed.count >= 9 else { return Data() }
        let payload = framed.subdata(in: 3..<(framed.count - 6))
        var pt = Data(capacity: payload.count)
        for (i, b) in payload.enumerated() { pt.append(b ^ pad1[i & 15]) }
        var out = framed.prefix(3)
        out.append(pt)
        return out
    }

    // MARK: Enc2

    func establish(authParam: Data) {
        self.authParam = authParam
        key2 = NSha1.digest([pwd16, NSha1.pad16(authParam)]).prefix(16)
    }

    private func iv(_ counter: Int) -> Data {
        var d = Data([0x00, 0x00, UInt8((counter >> 8) & 0xFF), UInt8(counter & 0xFF)])
        d.append((authParam ?? Data()).prefix(8))
        if d.count < 12 { d.append(Data(count: 12 - d.count)) }
        d.append(0x00)
        return d   // 13 bytes
    }

    private func keystream(_ counter: Int, round: Int) -> Data {
        guard let k2 = key2 else { return Data(count: 16) }
        var block = Data([0x01])
        block.append(iv(counter))
        block.append(contentsOf: [0x00, UInt8(round & 0xFF)])
        return NAES.ecbEncryptBlock(key: k2, block: block)
    }

    private func xorStream(_ counter: Int, _ data: Data) -> Data {
        var out = Data(capacity: data.count)
        var offset = 0
        var round = 1
        let arr = [UInt8](data)
        while offset < arr.count {
            let ks = [UInt8](keystream(counter, round: round))
            let n = min(16, arr.count - offset)
            for i in 0..<n { out.append(arr[offset + i] ^ ks[i]) }
            offset += 16
            round += 1
        }
        return out
    }

    private func mac(_ counter: Int, _ plain: Data) -> Data {
        guard let k2 = key2 else { return Data(count: 4) }
        let payload = plain.subdata(in: 3..<plain.count)
        let ivb = iv(counter)

        var firstBlock = Data([0x59])
        firstBlock.append(ivb)
        firstBlock.append(contentsOf: [0x00, UInt8(payload.count & 0xFF)])
        let first = NAES.ecbEncryptBlock(key: k2, block: firstBlock)

        var hdr = NSha1.pad16(plain.prefix(3))
        hdr = Data(zip(first, hdr).map { pair -> UInt8 in pair.0 ^ pair.1 })
        var chain = NAES.ecbEncryptBlock(key: k2, block: hdr)

        var offset = 0
        while offset < payload.count {
            let block = NSha1.pad16(payload.subdata(in: offset..<min(offset + 16, payload.count)))
            let mixed = Data(zip(chain, block).map { pair -> UInt8 in pair.0 ^ pair.1 })
            chain = NAES.ecbEncryptBlock(key: k2, block: mixed)
            offset += 16
        }

        var tailBlock = Data([0x01])
        tailBlock.append(ivb)
        tailBlock.append(contentsOf: [0x00, 0x00])
        let tail = NAES.ecbEncryptBlock(key: k2, block: tailBlock)
        return Data(zip(chain.prefix(4), tail.prefix(4)).map { pair -> UInt8 in pair.0 ^ pair.1 })
    }

    func encryptEnc2(counter: Int, plain: Data) -> Data {
        let ct = xorStream(counter, plain.subdata(in: 3..<plain.count))
        let m = mac(counter, plain)
        var out = plain.prefix(3)
        out.append(ct)
        out.append(m)
        out.append(contentsOf: [UInt8((counter >> 8) & 0xFF), UInt8(counter & 0xFF)])
        return out
    }

    struct Decrypted {
        let plain: Data
        let counter: Int
        let macOK: Bool
    }

    func decryptEnc2(_ framed: Data) throws -> Decrypted {
        guard framed.count >= 9 else { throw NBError.protocolError("Enc2 帧过短") }
        let counter = (Int(framed[framed.count - 2]) << 8) | Int(framed[framed.count - 1])
        let ct = framed.subdata(in: 3..<(framed.count - 6))
        let macIn = framed.subdata(in: (framed.count - 6)..<(framed.count - 2))
        var plain = framed.prefix(3)
        plain.append(xorStream(counter, ct))
        let calc = mac(counter, plain)
        return Decrypted(plain: plain, counter: counter, macOK: calc == macIn)
    }
}

extension NSha1 {
    static func pad16(_ d: Data) -> Data {
        var out = Data(d.prefix(16))
        if out.count < 16 { out.append(Data(count: 16 - out.count)) }
        return out
    }
}

