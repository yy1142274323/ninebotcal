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
        try await ble.connect(device)
        note("已连接 \(device.name)")
        try await handshake(password: password)
    }

    func handshake(password: String) async throws {
        guard password.count >= 16 else {
            throw NBError.handshake("BLE 密码需要 16 个字符")
        }
        let c = NBCipher(password: password)
        cipher = c
        phase = .precomm
        try await Task.sleep(nanoseconds: 300_000_000)
        note("发送 PRE_COMM（Enc1）")

        let reply = try await precommTransaction(NB.preComm, timeout: 8)
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
        guard let c = cipher else { return }

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
        guard let c = cipher else { throw NBError.notConnected }
        let framed = c.encryptEnc2(counter: nextCounter(), plain: plain)
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
        guard let c = cipher else { throw NBError.notConnected }
        let framed = c.encryptEnc2(counter: nextCounter(), plain: plain)
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
