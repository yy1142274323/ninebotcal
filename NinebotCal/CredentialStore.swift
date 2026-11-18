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

/// 凭据存储（Keychain，单条 JSON）+ 越狱环境下从官方九号 App 沙盒导入
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

    // MARK: - 从九号 App 沙盒导入（越狱 / TrollStore）

    struct ImportError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    func importFromNinebotApp() {
        importReport = []
        do {
            let found = try scanNinebotContainers()
            guard !found.isEmpty else {
                throw ImportError(message: "没有在 /var/mobile/Containers/Data/Application 下找到九号 App 的容器；请确认已安装并登录九号出行，且本 App 具备读取沙盒的权限（TrollStore 安装）。")
            }
            for (container, bundleID) in found {
                importReport.append("容器：\(bundleID) → \(container)")
                try importDatabases(in: container)
            }
            if items.isEmpty {
                importReport.append("未在数据库中取到 mac/password，请手动输入。")
            }
        } catch {
            importReport.append("导入失败：\(error.localizedDescription)")
        }
    }

    private func scanNinebotContainers() throws -> [(String, String)] {
        let root = "/var/mobile/Containers/Data/Application"
        let fm = FileManager.default
        guard let dirs = try? fm.contentsOfDirectory(atPath: root) else { return [] }
        var out: [(String, String)] = []
        for d in dirs {
            let path = root + "/" + d
            let meta = path + "/.com.apple.mobile_container_manager.metadata.plist"
            guard let dict = NSDictionary(contentsOfFile: meta) as? [String: Any],
                  let bid = dict["MCMMetadataIdentifier"] as? String else { continue }
            let lower = bid.lowercased()
            if lower.contains("ninebot") || lower.contains("segway") {
                out.append((path, bid))
            }
        }
        return out
    }

    private func importDatabases(in container: String) throws {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(atPath: container) else { return }
        for case let rel as String in enumerator {
            let lower = rel.lowercased()
            guard lower.hasSuffix(".sqlite") || lower.hasSuffix(".db") || lower.hasSuffix(".sqlite3") else { continue }
            let full = container + "/" + rel
            importReport.append("检查数据库：\(rel)")
            readDeviceTable(at: full)
        }
    }

    private func readDeviceTable(at path: String) {
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK, db != nil else {
            importReport.append("  打不开（权限或加密）")
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

        guard let table = tables.first(where: { $0.uppercased() == "DEVICE" })
                ?? tables.first(where: { $0.uppercased().contains("DEVICE") }) else { return }

        var cols: [String] = []
        if sqlite3_prepare_v2(db, "PRAGMA table_info(\(table))", -1, &stmt, nil) == SQLITE_OK {
            while sqlite3_step(stmt) == SQLITE_ROW {
                if let c = sqlite3_column_text(stmt, 1) { cols.append(String(cString: c)) }
            }
        }
        sqlite3_finalize(stmt)
        importReport.append("  表 \(table) 字段：\(cols.joined(separator: ","))")

        func pick(_ keys: [String]) -> String? {
            cols.first { c in keys.contains { c.lowercased().contains($0) } }
        }
        guard let macCol = pick(["mac"]), let pwdCol = pick(["password", "pwd", "pass", "key"]) else {
            importReport.append("  没有 mac/password 字段")
            return
        }
        let snCol = pick(["sn", "serial"]) ?? macCol

        let sql = "SELECT \(macCol), \(pwdCol), \(snCol) FROM \(table) WHERE \(macCol) IS NOT NULL"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }
        var count = 0
        while sqlite3_step(stmt) == SQLITE_ROW {
            func text(_ i: Int32) -> String {
                guard let c = sqlite3_column_text(stmt, i) else { return "" }
                return String(cString: c)
            }
            let mac = text(0), pwd = text(1), sn = text(2)
            guard !pwd.isEmpty else { continue }
            let cred = VehicleCredential(mac: mac, sn: sn, password: pwd, source: "ninebot-db")
            if !items.contains(where: { $0.id == cred.id }) { items.append(cred) }
            count += 1
        }
        if count > 0 {
            save()
            importReport.append("  导入 \(count) 条凭据")
        }
    }
}
