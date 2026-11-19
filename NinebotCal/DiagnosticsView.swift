import SwiftUI

/// 握手探针：在不确定密码编码 / 帧格式时，逐项试探车端反应
struct DiagnosticsView: View {
    @ObservedObject var session: VehicleSession
    @State private var log: [String] = []
    @State private var running = false

    var body: some View {
        List {
            Section {
                Text("连上车后逐项点。每一项都会把车端原始回包打出来；哪一项有回包，就说明这条路是对的。")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("1. 只监听") {
                Button {
                    Task { await run("监听 5 秒") { await session.probeListen(seconds: 5) } }
                } label: { Label("监听 5 秒（不发任何帧）", systemImage: "ear") }
            }

            Section("2. 明文帧（不加密）") {
                Button {
                    Task { await run("明文 PRE_COMM") { await session.probePlain(NB.preComm, wait: 3) } }
                } label: { Label("发明文 PRE_COMM", systemImage: "paperplane") }
                Button {
                    Task {
                        await run("明文读 0x1A") {
                            await session.probePlain(NB.frame(dst: NB.dstMain, cmd: NB.cmdRead, reg: 0x1A,
                                                             data: Data([0x02])), wait: 3)
                        }
                    }
                } label: { Label("发明文读 0x1A", systemImage: "doc.text.magnifyingglass") }
            }

            Section("3. Enc1 密码编码遍历") {
                Button {
                    Task { await run("密码编码遍历") { await session.probePasswordVariants() } }
                } label: { Label("逐个试 6 种密码编码", systemImage: "key.horizontal") }
                Text("会依次用不同编码派生 Enc1 密钥发 PRE_COMM，每次等 2.5 秒；一旦收到回包就停。")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("4. Enc2 直接试探") {
                Button {
                    Task { await run("Enc2 PRE_COMM") { await session.probeEnc2PreComm() } }
                } label: { Label("用 Enc2 发 PRE_COMM（无 authParam 时用零向量）", systemImage: "lock.rotation") }
            }

            Section("输出") {
                if running { ProgressView() }
                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(log.enumerated()), id: \.offset) { _, l in
                            Text(l).font(.caption2.monospaced())
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
                .frame(maxHeight: 380)
                if !log.isEmpty {
                    Button {
                        UIPasteboard.general.string = log.joined(separator: "\n")
                    } label: { Label("复制全部", systemImage: "doc.on.doc") }
                }
            }
        }
        .navigationTitle("握手探针")
        .navigationViewStyle(.stack)
    }

    private func run(_ title: String, _ block: @escaping () async -> Void) async {
        guard !running else { return }
        running = true
        add("=== \(title) ===")
        await block()
        add("=== 结束 ===")
        running = false
    }

    private func add(_ s: String) {
        log.append(s)
        if log.count > 500 { log.removeFirst(log.count - 500) }
    }
}
