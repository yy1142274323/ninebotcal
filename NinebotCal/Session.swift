import Foundation
import Combine

/// 与车辆的一次会话：PRE_COMM -> AUTH -> 寄存器读写
final class VehicleSession: ObservableObject {

    enum Phase: String {
        case disconnected = "未连接"
        case precomm = "预认证"
        case auth = "认证"
        case ready = "已就绪"
    }

    @Published var log: [String] = []
    @Published var phase: Phase = .disconnected
    @Published var values: [String: Int] = [:]
    @Published var snText: String = "—"
    @Published var profileRaw: Int?
    @Published var busy: String = ""
    @Published var lastError: String?

    let ble = BLEClient()
    private var cipher: NBCipher?
    private var counter: Int = 2
    private var waiters: [Waiter] = []
    private(set) var rxCount = 0
    private(set) var passwordKey = ""
    private var precommWaiter: Waiter?
    private var anyWaiter: Waiter?

    final class Waiter {
        var src: UInt8?
        var reg: UInt8?
        private var continuation: CheckedContinuation<NB.Frame, Error>?
        private var buffered: Result<NB.Frame, Error>?
        private(set) var finished = false
        var timer: DispatchWorkItem?

        func attach(_ c: CheckedContinuation<NB.Frame, Error>) {
            if let r = buffered {
                buffered = nil
                Self.resume(c, r)
            } else {
                continuation = c
            }
        }

        func finish(_ result: Result<NB.Frame, Error>) {
            guard !finished else { return }
            finished = true
            timer?.cancel()
            if let c = continuation {
                continuation = nil
                Self.resume(c, result)
            } else {
                buffered = result
            }
        }

        private static func resume(_ c: CheckedContinuation<NB.Frame, Error>, _ r: Result<NB.Frame, Error>) {
            switch r {
            case .success(let f): c.resume(returning: f)
            case .failure(let e): c.resume(throwing: e)
            }
        }
    }

    init() {
        ble.onNotification = { [weak self] data in self?.handle(data) }
        ble.onLog = { [weak self] s in self?.note(s) }
        ble.onDisconnect = { [weak self] err in
            guard let self else { return }
            self.phase = .disconnected
            self.cipher = nil
            self.failAll(NBError.notConnected)
        }
    }

    // MARK: - 日志

    func note(_ s: String) {
        let ts = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        log.append("[\(ts)] \(s)")
        if log.count > 400 { log.removeFirst(log.count - 400) }
    }

    // MARK: - 连接与握手

    func connectAndHandshake(device: Discovery, password: String) async throws {
        resetSession()
        try await ble.connect(device)
        note("已连接 \(device.name)")
        do {
            try await handshake(password: password)
        } catch {
            note("握手没有完成：\(error.localizedDescription)")
            note("自动诊断开始，约 40 秒，期间不要操作手机…")
            await autoDiagnose()
            note("自动诊断结束，正在自动上传日志…")
            do {
                let name = try await LogUpload.upload(log.joined(separator: "\n"))
                note("✅ 日志已自动上传：\(name)")
            } catch {
                note("自动上传失败：\(error.localizedDescription)（可点「上传日志到服务器」重试）")
            }
            throw error
        }
    }

    /// 握手失败后自动跑一遍探针，把结论写进日志
    func autoDiagnose() async {
        await probeListen(seconds: 3)
        await probePlain(NB.preComm, wait: 2)
        await probePlain(NB.frame(dst: NB.dstMain, cmd: NB.cmdRead, reg: 0x1A, data: Data([0x02])), wait: 2)
        await probePasswordVariants()
        await probeEnc2PreComm()
    }

    // MARK: - 握手探针

    func probeListen(seconds: Double) async {
        guard ble.isConnected else { note("探针：未连接"); return }
        rxCount = 0
        note("探针：只监听 \(Int(seconds))s，不发任何帧…")
        try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
        note("探针：收到 \(rxCount) 帧" + (rxCount == 0 ? "（车端没有主动发数据）" : ""))
    }

    func probePlain(_ frame: Data, wait: Double) async {
        guard ble.isConnected else { note("探针：未连接"); return }
        rxCount = 0
        note("探针 TX(明文) \(frame.hexString)")
        do { try await ble.send(frame) } catch {
            note("探针发送失败：\(error.localizedDescription)")
            return
        }
        try? await Task.sleep(nanoseconds: UInt64(wait * 1_000_000_000))
        note("探针：收到 \(rxCount) 帧" + (rxCount == 0 ? "（无回应）" : " ← 明文帧有回应"))
    }

    /// 用 6 种密码编码各发一次 Enc1 PRE_COMM，收到回包就停
    func probePasswordVariants() async {
        guard ble.isConnected else { note("探针：未连接"); return }
        guard !passwordKey.isEmpty else { note("探针：还没有密码，请先在连接页填一次"); return }
        let variants = NB.passwordVariants(passwordKey)
        note("探针：密码 \"\(passwordKey)\"，共 \(variants.count) 种编码")
        for (name, bytes) in variants {
            let c = NBCipher(pwd16: bytes)
            rxCount = 0
            let frame = c.encryptEnc1(NB.preComm)
            note("—— \(name)：\(bytes.hexString)")
            note("   TX \(frame.hexString)")
            do { try await ble.send(frame) } catch {
                note("   发送失败：\(error.localizedDescription)")
                continue
            }
            try? await Task.sleep(nanoseconds: 2_500_000_000)
            if rxCount > 0 {
                note("   ✅ 有回应！这个编码是对的：\(name)")
                cipher = c
                return
            } else {
                note("   无回应")
            }
        }
        note("探针：6 种编码都没有回应 —— 说明不是密码编码问题，是握手协议本身不同")
    }

    /// 假设 authParam 为零向量，直接用 Enc2 发 PRE_COMM
    func probeEnc2PreComm() async {
        guard ble.isConnected else { note("探针：未连接"); return }
        let zero = Data(count: 16)
        let c = NBCipher(password: passwordKey.isEmpty ? "0" : passwordKey)
        c.establish(authParam: zero)
        rxCount = 0
        let frame = c.encryptEnc2(counter: 2, plain: NB.preComm)
        note("探针 TX(Enc2 零向量) \(frame.hexString)")
        do { try await ble.send(frame) } catch { note("发送失败：\(error.localizedDescription)"); return }
        try? await Task.sleep(nanoseconds: 3_000_000_000)
        note("探针：收到 \(rxCount) 帧")
    }
    /// 每次重新连接前清空上一次的会话状态，避免残留等待者
    func resetSession() {
        failAll(NBError.handshake("会话重置"))
        cipher = nil
        counter = 2
        phase = .disconnected
        values.removeAll()
        profileRaw = nil
    }
    func handshake(password: String) async throws {
        guard !password.isEmpty else {
            throw NBError.handshake("请先填写 BLE 密码（5 位 PIN 也可以）")
        }
        if password.count > 16 { note("密码超过 16 字符，只用前 16 位") }
        note("密码长度 \(password.count)，按协议补零到 16 字节")
        passwordKey = password
        let c = NBCipher(password: password)
        cipher = c
        phase = .precomm
        try await Task.sleep(nanoseconds: 300_000_000)
        note("发送 PRE_COMM（Enc1）")

        note("等待 PRE_COMM 回复（8s）")
        let reply = try await precommTransaction(NB.preComm, timeout: 8)
        note("PRE_COMM 收到 \(reply.raw.count)B")
        guard reply.raw.count >= 37 else { throw NBError.handshake("PRE_COMM 回复过短") }
        let flag = reply.raw[6]
        let authParam = reply.raw.subdata(in: 7..<23)
        let snData = reply.raw.subdata(in: 23..<37)
        let snString = String(data: snData, encoding: .ascii)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !snString.isEmpty else { throw NBError.handshake("PRE_COMM 未返回车辆 SN") }

        snText = snString
        note("车辆 SN：\(snString)（状态字节 0x\(String(format: "%02X", flag))）")
        if flag == 0 { note("警告：车辆状态字节为 0，可能尚未配对过") }

        c.establish(authParam: authParam)
        phase = .auth
        counter = 2
        note("建立会话密钥，发送 AUTH（Enc2 ctr=2）")
        let authPlain = try NB.authFrame(sn: snData)
        _ = try await anyTransaction(plain: authPlain, timeout: 8)
        phase = .ready
        note("认证完成，会话已建立")
    }

    // MARK: - 数据收发

    private func nextCounter() -> Int {
        let c = counter
        counter += 1
        return c
    }

    private func handle(_ data: Data) {
        rxCount += 1
        note("RX \(data.count)B  \(data.hexString.prefix(48))")
        guard let c = cipher else {
            note("收到数据但还没有密钥（握手未开始）")
            return
        }

        if phase == .precomm {
            let plain = c.decryptEnc1(data)
            guard plain.count >= 7 else { return }
            if let w = precommWaiter {
                precommWaiter = nil
                guard let f = try? NB.parse(plain) else {
                    w.finish(.failure(NBError.protocolError("PRE_COMM 回包解析失败")))
                    return
                }
                w.finish(.success(f))
            }
            return
        }

        do {
            let dec = try c.decryptEnc2(data)
            if !dec.macOK { note("MAC 校验失败（继续尝试解析）") }
            counter = max(counter, dec.counter + 1)
            let f = try NB.parse(dec.plain)
            dispatch(f)
        } catch {
            note("收到无法解密的帧：\(data.hexString.prefix(40))")
        }
    }

    private func dispatch(_ f: NB.Frame) {
        if let w = anyWaiter {
            anyWaiter = nil
            w.finish(.success(f))
            return
        }
        guard f.cmd == NB.cmdAck else { return }
        if let idx = waiters.firstIndex(where: { w in
            w.src == f.src && (w.reg == nil || w.reg == f.reg)
        }) {
            let w = waiters.remove(at: idx)
            w.finish(.success(f))
        }
    }

    private func failAll(_ e: Error) {
        for w in waiters { w.finish(.failure(e)) }
        waiters.removeAll()
        precommWaiter?.finish(.failure(e))
        precommWaiter = nil
        anyWaiter?.finish(.failure(e))
        anyWaiter = nil
    }

    private func precommTransaction(_ plain: Data, timeout: Double) async throws -> NB.Frame {
        guard let c = cipher else { throw NBError.notConnected }
        let framed = c.encryptEnc1(plain)
        let waiter = Waiter()
        precommWaiter = waiter
        let work = DispatchWorkItem { [weak self] in
            self?.precommWaiter = nil
            waiter.finish(.failure(NBError.timeout("PRE_COMM 无回复")))
        }
        waiter.timer = work
        DispatchQueue.main.asyncAfter(deadline: .now() + timeout, execute: work)

        try await ble.send(framed)
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<NB.Frame, Error>) in
            waiter.attach(cont)
        }
    }

    /// AUTH 的应答形态不固定：收到任意可解密帧即视为认证已处理
    private func anyTransaction(plain: Data, timeout: Double) async throws -> NB.Frame {
        guard let c = cipher else {
            note("发送失败：会话密钥还没建立，请先在「连接」页点车辆完成握手")
            throw NBError.handshake("会话未建立（请先点车辆连接）")
        }
        let ctr = nextCounter()
        let framed = c.encryptEnc2(counter: ctr, plain: plain)
        note("TX ctr=\(ctr)  \(plain.hexString.prefix(40))")
        let waiter = Waiter()
        anyWaiter = waiter
        let work = DispatchWorkItem { [weak self] in
            self?.anyWaiter = nil
            waiter.finish(.failure(NBError.timeout("AUTH 无回复")))
        }
        waiter.timer = work
        DispatchQueue.main.asyncAfter(deadline: .now() + timeout, execute: work)

        do {
            try await ble.send(framed)
        } catch {
            waiter.finish(.failure(error))
            throw error
        }
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<NB.Frame, Error>) in
            waiter.attach(cont)
        }
    }
    private func transaction(plain: Data, expectSrc: UInt8?, expectReg: UInt8?,
                             timeout: Double, allowAnyReg: Bool = false) async throws -> NB.Frame {
        guard let c = cipher else {
            note("发送失败：会话密钥还没建立，请先在「连接」页点车辆完成握手")
            throw NBError.handshake("会话未建立（请先点车辆连接）")
        }
        let ctr = nextCounter()
        let framed = c.encryptEnc2(counter: ctr, plain: plain)
        note("TX ctr=\(ctr)  \(plain.hexString.prefix(40))")
        let waiter = Waiter()
        waiter.src = expectSrc
        waiter.reg = allowAnyReg ? nil : expectReg
        waiters.append(waiter)

        let work = DispatchWorkItem { [weak self] in
            self?.waiters.removeAll { $0 === waiter }
            waiter.finish(.failure(NBError.timeout("设备无回复")))
        }
        waiter.timer = work
        DispatchQueue.main.asyncAfter(deadline: .now() + timeout, execute: work)

        do {
            try await ble.send(framed)
        } catch {
            waiter.finish(.failure(error))
            throw error
        }
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<NB.Frame, Error>) in
            waiter.attach(cont)
        }
    }

    // MARK: - 读取

    @discardableResult
    func read(_ r: NB.Register) async throws -> Int {
        let f = try await transaction(plain: NB.readFrame(r), expectSrc: r.dst, expectReg: r.reg, timeout: 4)
        let v: Int
        if r.len == 1 {
            v = f.payload.count >= 1 ? Int(f.payload[0]) : -1
        } else {
            v = NB.le16(f.payload)
        }
        values[r.key] = v
        return v
    }

    func readAll() async {
        guard phase == .ready, cipher != nil, ble.isConnected else {
            note("读取被跳过：会话未就绪（当前 \(phase.rawValue)）")
            busy = ""
            return
        }
        busy = "读取车辆数据…"
        for r in NB.registers {
            do {
                let v = try await read(r)
                note(String(format: "读取 %@ (0x%02X/0x%02X) = %d %@", r.title, r.dst, r.reg, v, r.unit))
                try await Task.sleep(nanoseconds: 180_000_000)
            } catch {
                note("读取 \(r.title) 失败：\(error.localizedDescription)")
            }
        }
        if let p = values["dis_profile"], p >= 0 { profileRaw = p }
        busy = ""
    }

    // MARK: - 写入（仪表盘档位）

    struct WriteOutcome {
        let before: UInt8
        let target: UInt8
        let readback: UInt8?
        let verified: Bool
    }

    func writeDISProfile(voltage: Int, capacityIndex: Int?) async throws -> WriteOutcome {
        guard phase == .ready else { throw NBError.handshake("会话未就绪") }
        guard snText.uppercased().hasPrefix("N") == false else {
            throw NBError.protocolError("该序列号以 N 开头，本工具仅提供只读")
        }

        defer { busy = "" }
        busy = "写入前重新读取当前档位…"
        let before = try await read(NB.register("dis_profile")!)
        guard before >= 0 && before <= 255 else { throw NBError.protocolError("当前档位读取无效") }
        let beforeByte = UInt8(before & 0xFF)
        let target = try NB.makeProfile(current: beforeByte, voltage: voltage, capacityIndex: capacityIndex)
        guard NB.profileVoltage(beforeByte) != nil else {
            throw NBError.protocolError("当前配置值 0x\(String(format: "%02X", beforeByte)) 无法识别，禁止猜测写入")
        }
        note(String(format: "写入前 0x%02X（%d），目标 0x%02X（%d）", beforeByte,
                    NB.profileVoltage(beforeByte) ?? -1, target, voltage))

        if target == beforeByte {
            note("仪表已是目标档位，未发送写入")
            return WriteOutcome(before: beforeByte, target: target, readback: beforeByte, verified: true)
        }

        busy = "正在写入仪表档位…"
        let plain = NB.disWriteFrame(profile: target)
        do {
            _ = try await transaction(plain: plain, expectSrc: NB.dstMain, expectReg: 0x92,
                                      timeout: 4, allowAnyReg: true)
            note("收到写入应答（WRITE_ACK）")
        } catch {
            note("写入应答未收到：\(error.localizedDescription)；继续回读确认，不重复写")
        }
        busy = "回读校验…"
        if let rb = try await verifyProfile(target: target) {
            return WriteOutcome(before: beforeByte, target: target, readback: rb, verified: rb == target)
        }
        return WriteOutcome(before: beforeByte, target: target, readback: nil, verified: false)
    }

    // MARK: - 容量写入（0x1C，LE16，单位 mAh）

    struct CapacityOutcome {
        let before: Int
        let target: Int
        let readback: Int?
        let verified: Bool
        let usedDst: UInt8?
    }

    /// 0x1C 是原始容量（mAh，小端 16 位），不受仪表档位表限制，50Ah 这类值只能走这里。
    /// 先按 0x01（中控）写，回读不对再试 0x10（仪表），全程只写一次、靠回读判定。
    func writeCapacity(mAh: Int) async throws -> CapacityOutcome {
        guard phase == .ready else { throw NBError.handshake("会话未就绪") }
        guard mAh > 0, mAh <= 65535 else { throw NBError.invalidArgument("容量必须在 1…65535 mAh") }
        guard !snText.uppercased().hasPrefix("N") else {
            throw NBError.protocolError("该序列号以 N 开头，本工具仅提供只读")
        }
        defer { busy = "" }

        busy = "读取当前容量…"
        let before = try await read(NB.register("dis_capacity")!)
        note("当前 0x1C = \(before) mAh")

        let data = Data([UInt8(mAh & 0xFF), UInt8((mAh >> 8) & 0xFF)])
        for dst in [NB.dstMain, NB.dstDIS] {
            busy = String(format: "写入容量 → dst 0x%02X", dst)
            let plain = NB.frame(dst: dst, cmd: NB.cmdWrite, reg: 0x1C, data: data)
            note(String(format: "写 0x1C dst=0x%02X data=%02X %02X", dst, data[0], data[1]))
            do {
                _ = try await transaction(plain: plain, expectSrc: dst, expectReg: 0x1C,
                                          timeout: 4, allowAnyReg: true)
                note("收到写入应答")
            } catch {
                note("写入应答未收到：\(error.localizedDescription)，继续回读")
            }
            busy = "回读容量…"
            for i in 0..<4 {
                if let v = try? await read(NB.register("dis_capacity")!) {
                    note("回读 \(i + 1)/4：\(v) mAh")
                    if v == mAh {
                        return CapacityOutcome(before: before, target: mAh, readback: v, verified: true, usedDst: dst)
                    }
                }
                try await Task.sleep(nanoseconds: 450_000_000)
            }
        }
        return CapacityOutcome(before: before, target: mAh, readback: nil, verified: false, usedDst: nil)
    }
    private func verifyProfile(target: UInt8) async throws -> UInt8? {
        for i in 0..<4 {
            do {
                let v = try await read(NB.register("dis_profile")!)
                let b = UInt8(v & 0xFF)
                note(String(format: "回读 %d/4：0x%02X", i + 1, b))
                if b == target { return b }
            } catch {
                note("回读失败：\(error.localizedDescription)")
            }
            try await Task.sleep(nanoseconds: 450_000_000)
        }
        return nil
    }

    func restore(profile: UInt8) async throws -> Bool {
        defer { busy = "" }
        busy = "恢复原档位…"
        do {
            _ = try await transaction(plain: NB.disWriteFrame(profile: profile), expectSrc: NB.dstMain,
                                      expectReg: 0x92, timeout: 4, allowAnyReg: true)
        } catch {
            note("恢复应答未收到：\(error.localizedDescription)；继续回读")
        }
        if let v = try await verifyProfile(target: profile) { return v == profile }
        return false
    }
}
