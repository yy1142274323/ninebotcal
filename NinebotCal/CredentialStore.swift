import Foundation
import Security
import SQLite3

struct VehicleCredential: Codable, Identifiable, Hashable {
    var mac: String
    var sn: String
    var password: String
    var source: String
    var id: String { mac + "|" + sn }
}

/// 凭据存储（Keychain 单条 JSON）+ 三种导入方式：
/// 1) 自动扫九号 App 沙盒   2) 从文件导入 .db/.sqlite   3) 手动输入
final class CredentialStore: ObservableObject {

    @Published var items: [VehicleCredential] = []
    @Published var importReport: [String] = []

    private let service = "com.bfg.ninebotcal.credentials"
    private let account = "vehicles"

    init() { load() }

    // MARK: - 持久化

    func load() {
        guard let data = keychainRead() else { items = []; return }
        items = (try? JSONDecoder().decode([VehicleCredential].self, from: data)) ?? []
    }

    func save() {
        guard let data = try? JSONEncoder().encode(items) else { return }
        keychainWrite(data)
    }

    func add(_ c: VehicleCredential) {
        if let i = items.firstIndex(where: { $0.id == c.id }) { items[i] = c } else { items.append(c) }
        save()
    }

    func remove(_ c: VehicleCredential) {
        items.removeAll { $0.id == c.id }
        save()
    }

    func credential(forMAC mac: String) -> VehicleCredential? {
        let norm = mac.uppercased().replacingOccurrences(of: ":", with: "")
        return items.first { $0.mac.uppercased().replacingOccurrences(of: ":", with: "") == norm }
    }

    private func keychainQuery() -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    private func keychainRead() -> Data? {
        var q = keychainQuery()
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    private func keychainWrite(_ data: Data) {
        var q = keychainQuery()
        SecItemDelete(q as CFDictionary)
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(q as CFDictionary, nil)
    }

    // MARK: - 方式 1：扫九号 App 沙盒

    func importFromNinebotApp() {
        importReport = []
        do {
            let root = "/var/mobile/Containers/Data/Application"
            let fm = FileManager.default
            var isDir: ObjCBool = false
            let exists = fm.fileExists(atPath: root, isDirectory: &isDir)
            append("权限自检：路径存在=\(exists) 是目录=\(isDir.boolValue)")

            let dirs: [String]
            do {
                dirs = try fm.contentsOfDirectory(atPath: root)
            } catch {
                let ns = error as NSError
                append("列目录失败：\(error.localizedDescription)（errno=\(ns.code)）")
                append("判定：本 App 没有跨沙盒权限。需要 entitlements 里的")
                append("  com.apple.private.security.storage.AppDataContainers = true")
                append("  com.apple.private.security.no-sandbox = true")
                report("无跨沙盒权限")
                return
            }
            append("容器总数：\(dirs.count)")

            var ninebot: [(String, String)] = []
            var sample: [String] = []
            var map: [String] = []
            for d in dirs {
                let path = root + "/" + d
                guard let dict = NSDictionary(contentsOfFile: path + "/.com.apple.mobile_container_manager.metadata.plist") as? [String: Any],
                      let bid = dict["MCMMetadataIdentifier"] as? String else { continue }
                map.append("\(d)\t\(bid)")
                let low = bid.lowercased()
                if low.contains("ninebot") || low.contains("segway") || low.contains("nb.") || low.contains("scooter") {
                    ninebot.append((path, bid))
                } else if sample.count < 6 {
                    sample.append(bid)
                }
            }
            // 落盘一份 UUID -> bundle id 对照表，方便在 Filza / 文件里查
            let mapPath = NSHomeDirectory() + "/Documents/containers.txt"
            try? map.sorted().joined(separator: "\n").write(toFile: mapPath, atomically: true, encoding: .utf8)
            append("对照表已写入 Documents/containers.txt（\(map.count) 条）")

            if ninebot.isEmpty {
                append("没有匹配到 ninebot/segway 容器。随机列几个已装 App 的 bundle id：")
                sample.forEach { append("  · \($0)") }
                append("→ 说明这台 iPhone 上没装九号出行，或它的 bundle id 不含 ninebot")
                append("对照表见 Documents/containers.txt，可用「文件」App 打开本 App 的文件夹查看")
                report("未找到九号容器")
                return
            }

            for (path, bid) in ninebot {
                append("容器：\(bid)")
                importDatabases(in: path)
            }
            if items.isEmpty {
                append("容器找到了，但没取到 mac/password。常见原因：")
                append("  · 这台 iPhone 没登录过九号出行，或没在这台手机上配对过这辆车")
                append("  · 凭据存在 Keychain 而不是 SQLite")
                append("→ 用「从文件导入数据库」或直接在安卓上取密码后手输")
            }
        } catch {
            append("导入失败：\(error.localizedDescription)")
        }
        report(importReport.joined(separator: "\n"))
    }

    private func importDatabases(in container: String) {
        let fm = FileManager.default
        guard let en = fm.enumerator(atPath: container) else { return }
        var found = 0
        for case let rel as String in en {
            let low = rel.lowercased()
            guard low.hasSuffix(".sqlite") || low.hasSuffix(".db") || low.hasSuffix(".sqlite3") else { continue }
            found += 1
            let full = container + "/" + rel
            let attrs = try? fm.attributesOfItem(atPath: full)
            let size = (attrs?[.size] as? Int) ?? 0
            append("  库：\(rel)（\(size) B）")
            readDeviceTable(at: full, label: rel)
        }
        if found == 0 { append("  该容器内没有 .sqlite/.db 文件") }
    }

    // MARK: - 方式 2：从文件导入

    func importDatabase(at path: String) {
        importReport = []
        let name = (path as NSString).lastPathComponent
        append("导入文件：\(name)")
        // 复制到可写目录（顺带把 -wal/-shm 一起，避免读到旧数据）
        let tmp = NSTemporaryDirectory() + "imported-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        let dst = tmp + "/" + name
        do {
            try FileManager.default.copyItem(atPath: path, toPath: dst)
            for suffix in ["-wal", "-shm"] {
                if FileManager.default.fileExists(atPath: path + suffix) {
                    try? FileManager.default.copyItem(atPath: path + suffix, toPath: dst + suffix)
                }
            }
        } catch {
            append("复制失败：\(error.localizedDescription)")
            report(importReport.joined(separator: "\n"))
            return
        }
        readDeviceTable(at: dst, label: name)
        if items.isEmpty { append("该库中没有符合条件的 mac/password 记录") }
        report(importReport.joined(separator: "\n"))
    }

    // MARK: - SQLite 解析

    private func readDeviceTable(at path: String, label: String) {
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK, db != nil else {
            append("  打不开（加密或权限不足）")
            return
        }
        defer { sqlite3_close(db) }

        var tables: [String] = []
        var stmt: OpaquePointer?
        if sqlite3_prepare_v2(db, "SELECT name FROM sqlite_master WHERE type='table'", -1, &stmt, nil) == SQLITE_OK {
            while sqlite3_step(stmt) == SQLITE_ROW {
                if let c = sqlite3_column_text(stmt, 0) { tables.append(String(cString: c)) }
            }
        }
        sqlite3_finalize(stmt)
        append("  表：\(tables.prefix(12).joined(separator: ","))\(tables.count > 12 ? " …" : "")")

        // 优先 DEVICE，其次任何带 mac+pass 字段的表
        var candidates: [String] = []
        if let t = tables.first(where: { $0.uppercased() == "DEVICE" }) { candidates.append(t) }
        candidates.append(contentsOf: tables.filter { $0.uppercased() != "DEVICE" })

        for table in candidates {
            var cols: [String] = []
            if sqlite3_prepare_v2(db, "PRAGMA table_info(\(table))", -1, &stmt, nil) == SQLITE_OK {
                while sqlite3_step(stmt) == SQLITE_ROW {
                    if let c = sqlite3_column_text(stmt, 1) { cols.append(String(cString: c)) }
                }
            }
            sqlite3_finalize(stmt)
            guard !cols.isEmpty else { continue }

            func pick(_ keys: [String]) -> String? {
                cols.first { c in keys.contains { c.lowercased().contains($0) } }
            }
            guard let macCol = pick(["mac"]),
                  let pwdCol = pick(["password", "pwd", "pass", "key", "secret"]) else { continue }

            let snCol = pick(["sn", "serial"]) ?? macCol
            let sql = "SELECT \(macCol), \(pwdCol), \(snCol) FROM \(table)"
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { continue }
            defer { sqlite3_finalize(stmt) }

            var count = 0
            while sqlite3_step(stmt) == SQLITE_ROW {
                func text(_ i: Int32) -> String {
                    guard let c = sqlite3_column_text(stmt, i) else { return "" }
                    return String(cString: c)
                }
                let mac = text(0), pwd = text(1), sn = text(2)
                guard !pwd.isEmpty, !mac.isEmpty else { continue }
                let cred = VehicleCredential(mac: mac, sn: sn, password: pwd, source: label)
                if !items.contains(where: { $0.id == cred.id }) { items.append(cred) }
                count += 1
            }
            if count > 0 {
                save()
                append("  ✓ 表 \(table)（\(macCol)/\(pwdCol)）导入 \(count) 条")
                return
            } else {
                append("  表 \(table) 有 mac/password 字段但无有效行")
            }
        }
    }

    // MARK: - 工具

    private func append(_ s: String) { importReport.append(s) }

    /// 保存一份诊断文本，方便导出
    func report(_ text: String) {
        let path = NSHomeDirectory() + "/Documents/import-report.txt"
        try? text.write(toFile: path, atomically: true, encoding: .utf8)
    }
}
