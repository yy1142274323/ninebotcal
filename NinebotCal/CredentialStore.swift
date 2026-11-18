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

/// 凭据存储 + 从九号出行沙盒自动取凭据
/// iOS 版九号出行没有 Android 的 device-db，凭据通常落在：
///   Library/Preferences/cn.ninebot.segway.plist（NSUserDefaults）
///   或 App Group 容器（/var/mobile/Containers/Shared/AppGroup/…）
/// 所以除了 sqlite，还要翻 plist。
final class CredentialStore: ObservableObject {

    @Published var items: [VehicleCredential] = []
    @Published var importReport: [String] = []

    private let service = "com.bfg.ninebotcal.credentials"
    private let account = "vehicles"
    private let skipDirs: Set<String> = [
        "amap", "WebKit", "Caches", "Heimdallr", ".umeng", "StoreKit", "mapcache",
        "texture_cache", "__MACOSX", "ResourceLoadStatistics", "HTTPStorages", "snapshots",
        "com.apple", "bds", "Logs", "CrashReporter",
    ]

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

    func remove(_ c: VehicleCredential) { items.removeAll { $0.id == c.id }; save() }

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

    // MARK: - 自动导入

    func importFromNinebotApp() {
        importReport = []
        let fm = FileManager.default

        var targets: [(String, String)] = []
        var map: [String] = []

        // 1) 普通数据容器
        let dataRoot = "/var/mobile/Containers/Data/Application"
        if let dirs = try? fm.contentsOfDirectory(atPath: dataRoot) {
            append("数据容器：\(dirs.count) 个")
            for d in dirs {
                let path = dataRoot + "/" + d
                guard let bid = bundleId(of: path) else { continue }
                map.append("DATA\t\(d)\t\(bid)")
                if isNinebot(bid) { targets.append((path, bid)) }
            }
        } else {
            append("读不到 \(dataRoot) —— 权限被拒")
        }

        // 2) App Group 共享容器（九号可能把凭据放这）
        let groupRoot = "/var/mobile/Containers/Shared/AppGroup"
        if let dirs = try? fm.contentsOfDirectory(atPath: groupRoot) {
            append("App Group 容器：\(dirs.count) 个")
            for d in dirs {
                let path = groupRoot + "/" + d
                guard let bid = bundleId(of: path) else { continue }
                map.append("GROUP\t\(d)\t\(bid)")
                if isNinebot(bid) { targets.append((path, bid)) }
            }
        }

        let mapPath = NSHomeDirectory() + "/Documents/containers.txt"
        try? map.sorted().joined(separator: "\n").write(toFile: mapPath, atomically: true, encoding: .utf8)
        append("对照表已写入 Documents/containers.txt（\(map.count) 条）")

        guard !targets.isEmpty else {
            append("没有匹配到 ninebot/segway 容器")
            report(importReport.joined(separator: "\n"))
            return
        }

        for (path, bid) in targets {
            append("容器：\(bid)")
            scanContainer(path, label: bid)
        }

        if items.isEmpty {
            append("仍未取到 mac/password。两种可能：")
            append("  · 凭据在 Keychain（沙盒 App 读不到）")
            append("  · 这台 iPhone 没和这辆车配对过")
            append("→ 把上面 [plist] 段的输出发我，我按字段名判断下一步")
        }
        report(importReport.joined(separator: "\n"))
    }

    private func bundleId(of container: String) -> String? {
        let meta = container + "/.com.apple.mobile_container_manager.metadata.plist"
        guard let dict = NSDictionary(contentsOfFile: meta) as? [String: Any],
              let bid = dict["MCMMetadataIdentifier"] as? String else { return nil }
        return bid
    }

    private func isNinebot(_ bid: String) -> Bool {
        let low = bid.lowercased()
        return low.contains("ninebot") || low.contains("segway")
    }

    private func scanContainer(_ container: String, label: String) {
        let fm = FileManager.default
        guard let en = fm.enumerator(atPath: container) else { return }
        var plistCount = 0
        var dbCount = 0
        for case let rel as String in en {
            let comps = rel.split(separator: "/").map(String.init)
            if comps.contains(where: { skipDirs.contains($0) }) { continue }
            let low = rel.lowercased()
            let full = container + "/" + rel
            let attrs = try? fm.attributesOfItem(atPath: full)
            let size = (attrs?[.size] as? Int) ?? 0

            if low.hasSuffix("ble_devices.json") {
                parseBleDevices(at: full, label: rel)
            } else if low.hasSuffix(".plist") && size < 512_000 {
                plistCount += 1
                dumpPlist(at: full, label: rel, budget: 60)
            } else if low.hasSuffix(".sqlite") || low.hasSuffix(".db") || low.hasSuffix(".sqlite3") {
                dbCount += 1
                readDeviceTable(at: full, label: rel)
            } else if (low.hasSuffix(".json") || low.hasSuffix(".txt")) && size < 512_000 {
                grepText(at: full, label: rel)
            }
        }
        append("  扫描：plist \(plistCount) 个，数据库 \(dbCount) 个")
    }

    // MARK: - ble_devices.json（iOS 版的凭据库）

    /// 九号 iOS 把 BLE 凭据存在 Documents/rust_lib/kv/ble_devices.json，JSON-Lines 格式：
    /// {"k":"<peripheral-uuid>","v":{"bleType":4354,"encVer":2,"key":20035,"name":"…","sn":"…"}}
    /// key 就是 BLE 密码（5 位 PIN），SN 是 14 位车辆序列号。
    private func parseBleDevices(at path: String, label: String) {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return }
        var found = 0
        for line in text.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty,
                  let data = trimmed.data(using: .utf8),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let v = obj["v"] as? [String: Any],
                  let sn = v["sn"] as? String, !sn.isEmpty else { continue }
            let keyVal = v["key"]
            let pwd: String
            if let n = keyVal as? NSNumber { pwd = n.stringValue }
            else if let s = keyVal as? String { pwd = s }
            else { continue }
            let name = (v["name"] as? String) ?? ""
            let enc = (v["encVer"] as? NSNumber)?.stringValue ?? "?"
            let cred = VehicleCredential(mac: name.isEmpty ? sn : name, sn: sn,
                                         password: pwd, source: "ble_devices.json")
            if !items.contains(where: { $0.sn == sn && $0.password == pwd }) { items.append(cred) }
            append("  ✓ 车 \(name.isEmpty ? sn : name) · SN \(sn) · key=\(pwd) · encVer=\(enc)")
            found += 1
        }
        if found > 0 { save() }
    }
    // MARK: - plist 翻字段

    private func dumpPlist(at path: String, label: String, budget: Int) {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let any = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) else { return }
        var hits: [String] = []
        func flag(_ key: String) -> Bool {
            let k = key.lowercased()
            return k.contains("mac") || k.contains("ble") || k.contains("pass") || k.contains("pwd")
                || k.contains("key") || k.contains("secret") || k.contains("token")
                || k.contains("sn") || k.contains("device") || k.contains("vehicle") || k.contains("bike")
        }
        func walk(_ node: Any, _ path: String, _ depth: Int) {
            guard depth < 8, hits.count < budget else { return }
            if let dict = node as? [String: Any] {
                for (k, v) in dict.sorted(by: { $0.key < $1.key }) {
                    walk(v, path.isEmpty ? k : path + "." + k, depth + 1)
                }
            } else if let arr = node as? [Any] {
                for (i, v) in arr.prefix(30).enumerated() { walk(v, "\(path)[\(i)]", depth + 1) }
            } else if let s = node as? String {
                if flag(path), !s.isEmpty {
                    hits.append("  \(path) = \(s.count > 120 ? String(s.prefix(120)) + "…" : s)")
                }
            } else if let d = node as? Data {
                if flag(path) {
                    let hex = d.map { String(format: "%02x", $0) }.joined()
                    let ascii = String(data: d.prefix(32), encoding: .ascii) ?? ""
                    hits.append("  \(path) = <Data \(d.count)B> \(hex.prefix(48)) ascii=\(ascii)")
                }
            }
        }
        walk(any, "", 0)
        guard !hits.isEmpty else { return }
        append("[plist] \(label)")
        hits.forEach { append($0) }
    }

    private func grepText(at path: String, label: String) {
        guard let s = try? String(contentsOfFile: path, encoding: .utf8) else { return }
        let low = s.lowercased()
        guard low.contains("mac") || low.contains("ble") || low.contains("pass") else { return }
        append("[text] \(label)（\(s.count) 字符，含 mac/ble/pass 关键词）")
        append("  \(s.prefix(300).replacingOccurrences(of: "\n", with: " "))")
    }

    // MARK: - 从文件导入

    func importDatabase(at path: String) {
        importReport = []
        let name = (path as NSString).lastPathComponent
        append("导入文件：\(name)")
        let tmp = NSTemporaryDirectory() + "imported-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        let dst = tmp + "/" + name
        do {
            try FileManager.default.copyItem(atPath: path, toPath: dst)
            for suffix in ["-wal", "-shm"] where FileManager.default.fileExists(atPath: path + suffix) {
                try? FileManager.default.copyItem(atPath: path + suffix, toPath: dst + suffix)
            }
        } catch {
            append("复制失败：\(error.localizedDescription)")
            report(importReport.joined(separator: "\n"))
            return
        }
        if name.lowercased().hasSuffix(".plist") {
            dumpPlist(at: dst, label: name, budget: 80)
        } else {
            readDeviceTable(at: dst, label: name)
        }
        if items.isEmpty { append("该文件中没有可直接使用的 mac/password") }
        report(importReport.joined(separator: "\n"))
    }

    // MARK: - SQLite

    private func readDeviceTable(at path: String, label: String) {
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK, db != nil else { return }
        defer { sqlite3_close(db) }

        var tables: [String] = []
        var stmt: OpaquePointer?
        if sqlite3_prepare_v2(db, "SELECT name FROM sqlite_master WHERE type='table'", -1, &stmt, nil) == SQLITE_OK {
            while sqlite3_step(stmt) == SQLITE_ROW {
                if let c = sqlite3_column_text(stmt, 0) { tables.append(String(cString: c)) }
            }
        }
        sqlite3_finalize(stmt)
        guard !tables.isEmpty else { return }

        for table in tables {
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
            guard sqlite3_prepare_v2(db, "SELECT \(macCol), \(pwdCol), \(snCol) FROM \(table)", -1, &stmt, nil) == SQLITE_OK else { continue }
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
                append("  ✓ \(label) 表 \(table) 导入 \(count) 条")
                return
            }
        }
    }

    private func append(_ s: String) { importReport.append(s) }

    func report(_ text: String) {
        let path = NSHomeDirectory() + "/Documents/import-report.txt"
        try? text.write(toFile: path, atomically: true, encoding: .utf8)
    }
}
