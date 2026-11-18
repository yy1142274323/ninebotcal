import SwiftUI
import Combine

final class AppModel: ObservableObject {
    @Published var password: String = ""
    @Published var targetVoltage: Int = 60
    @Published var targetCapacitySlot: Int? = nil
    @Published var lastOutcome: VehicleSession.WriteOutcome?
    @Published var backupProfile: Int?
    @Published var busy = false
    @Published var alert: String?

    let session = VehicleSession()
    let store = CredentialStore()

    init() {
        if let first = store.items.first { password = first.password }
    }
}

struct RootView: View {
    @StateObject private var model = AppModel()

    var body: some View {
        TabView {
            ConnectView(model: model)
                .tabItem { Label("连接", systemImage: "dot.radiowaves.left.and.right") }
            CalibrateView(model: model)
                .tabItem { Label("校准", systemImage: "battery.75") }
            SettingsView(model: model)
                .tabItem { Label("设置", systemImage: "gearshape") }
        }
        .tint(.blue)
    }
}

// MARK: - 连接

struct ConnectView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var session: VehicleSession
    @ObservedObject var ble: BLEClient

    init(model: AppModel) {
        self.model = model
        self.session = model.session
        self.ble = model.session.ble
    }

    var body: some View {
        NavigationView {
            List {
                Section("状态") {
                    HStack {
                        Circle().fill(ble.isConnected ? Color.green : Color.gray)
                            .frame(width: 10, height: 10)
                        Text(ble.statusText)
                        Spacer()
                        Text(session.phase.rawValue).font(.caption).foregroundStyle(.secondary)
                    }
                    if ble.isConnected {
                        Button(role: .destructive) { ble.disconnect() } label: { Text("断开连接") }
                    }
                }

                Section {
                    SecureField("16 位 BLE 密码", text: $model.password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Text("来自官方九号出行 device-db 的 password 字段。可在「设置 → 从九号出行沙盒导入」，或手动填写。")
                        .font(.caption).foregroundStyle(.secondary)
                } header: { Text("凭据") }

                Section {
                    Button { ble.startScan() } label: {
                        Label("扫描车辆", systemImage: "magnifyingglass")
                    }
                    ForEach(ble.devices) { d in
                        Button { connect(d) } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(d.name)
                                    Text(String(format: "%d dBm%@", d.rssi, d.advertisesUART ? " · UART" : ""))
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                if d.isLikelyNinebot {
                                    Text("九号").font(.caption2)
                                        .padding(.horizontal, 6).padding(.vertical, 2)
                                        .background(Color.blue.opacity(0.15))
                                        .clipShape(Capsule())
                                }
                            }
                        }
                    }
                } header: { Text("附近设备") }
                footer: { Text("先唤醒车辆并靠近手机；关掉主机上的九号出行，避免占用蓝牙。") }
            }
            .navigationTitle("NinebotCal").navigationViewStyle(.stack)
            .overlay {
                if !session.busy.isEmpty { ProgressView().controlSize(.large) }
            }
            .alert("提示", isPresented: Binding(get: { model.alert != nil },
                                               set: { if !$0 { model.alert = nil } })) {
                Button("好") { model.alert = nil }
            } message: { Text(model.alert ?? "") }
        }
    }

    private func connect(_ d: Discovery) {
        Task {
            model.busy = true
            defer { model.busy = false }
            do {
                try await session.connectAndHandshake(device: d, password: model.password)
                await session.readAll()
                if model.backupProfile == nil { model.backupProfile = session.values["dis_profile"] }
            } catch {
                model.alert = error.localizedDescription
            }
        }
    }
}

// MARK: - 校准

struct CalibrateView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var session: VehicleSession
    @State private var confirmOpen = false
    @State private var riskAccepted = false

    init(model: AppModel) {
        self.model = model
        self.session = model.session
    }

    private var currentProfile: UInt8? {
        guard let v = session.values["dis_profile"], v >= 0, v <= 255 else { return nil }
        return UInt8(v)
    }

    var body: some View {
        NavigationView {
            List {
                Section("车辆") {
                    row("车辆 SN", session.snText)
                    row("会话", session.phase.rawValue)
                    if let p = currentProfile {
                        row("当前档位", String(format: "0x%02X · %d · %dAh", p,
                                              NB.profileVoltage(p) ?? -1, NB.profileCapacity(p) / 1000))
                    } else {
                        row("当前档位", "未读取")
                    }
                    row("仪表版本", session.values["dash_version"].map { String($0) } ?? "—")
                    row("计量模块", session.values["meter_ver"].map { String($0) } ?? "—")
                    row("电池电压", session.values["battery"].map { String(format: "%.1fV", Double($0) / 10.0) } ?? "—")
                }

                Section {
                    Picker("目标电压", selection: $model.targetVoltage) {
                        Text("48V").tag(48)
                        Text("60V").tag(60)
                        Text("72V").tag(72)
                    }
                    .pickerStyle(.segmented)

                    Toggle("同时修改容量槽位", isOn: Binding(
                        get: { model.targetCapacitySlot != nil },
                        set: { on in
                            model.targetCapacitySlot = on ? NB.profileSlot(currentProfile ?? 0x32) : nil
                        }))

                    if let slot = model.targetCapacitySlot {
                        Picker("容量槽位", selection: Binding(
                            get: { slot },
                            set: { model.targetCapacitySlot = $0 })) {
                            ForEach(0..<16, id: \.self) { i in
                                Text("\(i) · \(NB.capacitySlots[i] / 1000)Ah").tag(i)
                            }
                        }
                    }

                    if let p = currentProfile,
                       let t = try? NB.makeProfile(current: p, voltage: model.targetVoltage,
                                                   capacityIndex: model.targetCapacitySlot) {
                        row("将写入", String(format: "0x%02X · %d · %dAh", t, model.targetVoltage,
                                            NB.profileCapacity(t) / 1000))
                    }
                } header: { Text("目标参数") }
                footer: { Text("只改仪表盘 0x92 档位字节：低半字节=电压(1=72V,2=60V,3=48V)，高半字节=容量槽位。写入持久，断电不还原。") }

                Section {
                    Button {
                        Task {
                            await session.readAll()
                            if let p = session.values["dis_profile"], model.backupProfile == nil {
                                model.backupProfile = p
                            }
                        }
                    } label: { Label("重新读取车辆数据", systemImage: "arrow.clockwise") }

                    Button(role: .destructive) { confirmOpen = true } label: {
                        Label("写入并回读校验", systemImage: "square.and.arrow.down")
                    }
                    .disabled(session.phase != .ready || currentProfile == nil)
                }

                if let o = model.lastOutcome {
                    Section("上次写入结果") {
                        row("写入前", String(format: "0x%02X", o.before))
                        row("目标", String(format: "0x%02X", o.target))
                        row("回读", o.readback.map { String(format: "0x%02X", $0) } ?? "无回复")
                        row("结论", o.verified ? "已确认写入" : "未确认")
                    }
                }

                if let b = model.backupProfile {
                    Section("备份") {
                        row("本次备份", String(format: "0x%02X", b))
                        Button {
                            Task {
                                do {
                                    let ok = try await session.restore(profile: UInt8(b & 0xFF))
                                    model.alert = ok ? "已恢复原档位并回读确认" : "恢复指令已发送，但回读未确认"
                                } catch { model.alert = error.localizedDescription }
                            }
                        } label: { Label("恢复原档位", systemImage: "arrow.uturn.backward") }
                    }
                }

                Section("寄存器") {
                    ForEach(NB.registers, id: \.key) { r in
                        row(r.title, session.values[r.key].map { "\($0)" } ?? "—")
                    }
                }
            }
            .navigationTitle("电量校准").navigationViewStyle(.stack)
            .sheet(isPresented: $confirmOpen) { confirmSheet }
            .alert("提示", isPresented: Binding(get: { model.alert != nil },
                                               set: { if !$0 { model.alert = nil } })) {
                Button("好") { model.alert = nil }
            } message: { Text(model.alert ?? "") }
        }
    }

    private var confirmSheet: some View {
        NavigationView {
            List {
                Section {
                    Text("写入前会自动重新读取当前档位并留作备份；写入后立即回读校验，不通过不会连续重试。")
                }
                Section {
                    Text("已知风险（与原版 BFG 提示一致）：\n• 仪表盘配置是持久写入，断电不还原；\n• 已有写入后计量模块损坏的实车案例，可能导致无法启动或显示异常；\n• 备份不保证在异常后仍能恢复；\n• 更换计量模块后仪表还可能再次下发旧配置。")
                        .font(.callout)
                }
                Toggle("我已核对车辆与目标参数，并理解上述风险", isOn: $riskAccepted)
                Section {
                    Button("确认写入") {
                        confirmOpen = false
                        Task { await doWrite() }
                    }
                    .disabled(!riskAccepted)
                }
            }
            .navigationTitle("写入确认").navigationViewStyle(.stack)
        }
    }

    private func doWrite() async {
        do {
            let outcome = try await session.writeDISProfile(voltage: model.targetVoltage,
                                                            capacityIndex: model.targetCapacitySlot)
            model.lastOutcome = outcome
            if model.backupProfile == nil { model.backupProfile = Int(outcome.before) }
            model.alert = outcome.verified
                ? String(format: "写入已确认：0x%02X → 0x%02X", outcome.before, outcome.target)
                : "写入指令已发送，但回读未确认；请重新连接读取当前参数，勿连续重复写入。"
        } catch {
            model.alert = error.localizedDescription
        }
        riskAccepted = false
    }

    private func row(_ k: String, _ v: String) -> some View {
        HStack { Text(k); Spacer(); Text(v).foregroundStyle(.secondary) }
    }
}

// MARK: - 设置

struct SettingsView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var store: CredentialStore
    @ObservedObject var session: VehicleSession

    init(model: AppModel) {
        self.model = model
        self.store = model.store
        self.session = model.session
    }

    var body: some View {
        NavigationView {
            List {
                Section("已保存凭据（Keychain）") {
                    ForEach(store.items) { c in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(c.mac).font(.callout)
                            Text("SN \(c.sn) · 密码 \(c.password.count) 字符 · \(c.source)")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        .swipeActions {
                            Button(role: .destructive) { store.remove(c) } label: { Text("删除") }
                            Button { model.password = c.password } label: { Text("使用") }.tint(.blue)
                        }
                    }
                    if store.items.isEmpty { Text("还没有保存的凭据").foregroundStyle(.secondary) }
                }

                Section {
                    Button { store.importFromNinebotApp() } label: {
                        Label("从九号出行沙盒导入", systemImage: "tray.and.arrow.down")
                    }
                    ForEach(store.importReport, id: \.self) { line in
                        Text(line).font(.caption2).foregroundStyle(.secondary)
                    }
                } header: { Text("越狱导入") }
                footer: { Text("需要 TrollStore / 无沙盒权限的安装方式，才能读取 /var/mobile/Containers/Data/Application 下官方 App 的 SQLite。") }

                Section("协议") {
                    Text("UART 6e400001-…\nTX 6e400002-… / RX 6e400003-…\n帧 5A A5 LEN SRC DST CMD REG DATA\nEnc1 SHA1(pwd‖KEY0) + AES-ECB 流\nEnc2 SHA1(pwd‖authParam) + CBC-MAC")
                        .font(.caption.monospaced())
                }

                Section("运行日志") {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(Array(session.log.enumerated()), id: \.offset) { _, l in
                                Text(l).font(.caption2.monospaced())
                            }
                        }
                    }
                    .frame(maxHeight: 260)
                }
            }
            .navigationTitle("设置").navigationViewStyle(.stack)
        }
    }
}
