import Foundation

/// 把运行日志 POST 到自己的服务器，省得复制粘贴
enum LogUpload {
    static let endpoint = URL(string: "https://ipa.oooai.org/ninebotcal/log")!
    static let token = "nbcal2026"

    static func upload(_ text: String) async throws -> String {
        var req = URLRequest(url: endpoint)
        req.httpMethod = "POST"
        req.timeoutInterval = 25
        req.setValue(token, forHTTPHeaderField: "X-Token")
        req.setValue("text/plain; charset=utf-8", forHTTPHeaderField: "Content-Type")
        req.httpBody = Data(text.utf8)
        let (data, resp) = try await URLSession.shared.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? -1
        guard code == 200 else {
            throw NBError.protocolError("上传失败 HTTP \(code)")
        }
        return String(data: data, encoding: .utf8) ?? "ok"
    }
}
