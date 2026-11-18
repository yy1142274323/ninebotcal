import Foundation
import CoreBluetooth

struct Discovery: Identifiable, Equatable {
    let id: UUID
    let name: String
    let rssi: Int
    let advertisesUART: Bool
    let isLikelyNinebot: Bool
}

final class BLEClient: NSObject, ObservableObject {

    @Published var devices: [Discovery] = []
    @Published var statusText: String = "未开始"
    @Published var isConnected: Bool = false
    @Published var connectedName: String = ""
    @Published var bluetoothState: CBManagerState = .unknown

    private var central: CBCentralManager!
    private var peripheral: CBPeripheral?
    private var txChar: CBCharacteristic?
    private var rxChar: CBCharacteristic?
    private var discovered: [UUID: CBPeripheral] = [:]
    private var connectContinuation: CheckedContinuation<Void, Error>?
    private var serviceContinuation: CheckedContinuation<Void, Error>?
    private var writeContinuations: [CheckedContinuation<Void, Error>] = []

    var onNotification: ((Data) -> Void)?
    var onDisconnect: ((Error?) -> Void)?

    override init() {
        super.init()
        central = CBCentralManager(delegate: self, queue: .main,
                                   options: [CBCentralManagerOptionShowPowerAlertKey: true])
    }

    // MARK: - 扫描

    func startScan() {
        guard central.state == .poweredOn else {
            statusText = "蓝牙不可用：\(stateText(central.state))"
            return
        }
        devices.removeAll()
        discovered.removeAll()
        statusText = "扫描中…请唤醒车辆并靠近手机"
        central.scanForPeripherals(withServices: nil,
                                   options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
    }

    func stopScan() {
        central.stopScan()
        if statusText.hasPrefix("扫描中") { statusText = "扫描结束" }
    }

    // MARK: - 连接

    func connect(_ d: Discovery) async throws {
        guard central.state == .poweredOn else { throw NBError.handshake("蓝牙未开启") }
        guard let p = discovered[d.id] ?? central.retrievePeripherals(withIdentifiers: [d.id]).first else {
            throw NBError.handshake("找不到设备，请重新扫描")
        }
        stopScan()
        peripheral = p
        p.delegate = self
        statusText = "连接中…"
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            self.connectContinuation = cont
            central.connect(p, options: nil)
        }
        statusText = "发现服务…"
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            self.serviceContinuation = cont
            p.discoverServices([CBUUID(string: NB.svcUART)])
        }
    }

    func disconnect() {
        if let p = peripheral { central.cancelPeripheralConnection(p) }
        isConnected = false
        txChar = nil
        rxChar = nil
    }

    // MARK: - 发送

    func send(_ data: Data) async throws {
        guard let p = peripheral, let tx = txChar, p.state == .connected else {
            throw NBError.notConnected
        }
        let type: CBCharacteristicWriteType = tx.properties.contains(.write) ? .withResponse : .withoutResponse
        let maxLen = p.maximumWriteValueLength(for: type)
        var offset = 0
        while offset < data.count {
            let chunk = data.subdata(in: offset..<min(offset + maxLen, data.count))
            if type == .withResponse {
                try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                    self.writeContinuations.append(cont)
                    p.writeValue(chunk, for: tx, type: .withResponse)
                }
            } else {
                p.writeValue(chunk, for: tx, type: .withoutResponse)
                try await Task.sleep(nanoseconds: 12_000_000)
            }
            offset += chunk.count
        }
    }

    private func stateText(_ s: CBManagerState) -> String {
        switch s {
        case .poweredOn: return "已开启"
        case .poweredOff: return "已关闭"
        case .unauthorized: return "未授权"
        case .unsupported: return "不支持"
        case .resetting: return "重置中"
        default: return "未知"
        }
    }
}

extension BLEClient: CBCentralManagerDelegate {

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        bluetoothState = central.state
        if central.state != .poweredOn { statusText = "蓝牙不可用：\(stateText(central.state))" }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        let advServices = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID]) ?? []
        let uart = advServices.contains { $0.uuidString.lowercased() == NB.svcUART }
        let name = peripheral.name
            ?? (advertisementData[CBAdvertisementDataLocalNameKey] as? String)
            ?? "未命名设备"
        let lower = name.lowercased()
        let likely = uart || lower.contains("ninebot") || lower.contains("segway")
            || lower.contains("nb") || lower.contains("mi ") || lower.contains("九号")

        discovered[peripheral.identifier] = peripheral
        if devices.contains(where: { $0.id == peripheral.identifier }) { return }
        if RSSI.intValue < -95 && !likely { return }

        devices.append(Discovery(id: peripheral.identifier, name: name, rssi: RSSI.intValue,
                                 advertisesUART: uart, isLikelyNinebot: likely))
        devices.sort { a, b in
            if a.isLikelyNinebot != b.isLikelyNinebot { return a.isLikelyNinebot }
            return a.rssi > b.rssi
        }
        statusText = "已发现 \(devices.count) 个设备"
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        isConnected = true
        connectedName = peripheral.name ?? "车辆"
        statusText = "已连接，发现服务…"
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        let err = error ?? NBError.handshake("连接失败")
        connectContinuation?.resume(throwing: err)
        connectContinuation = nil
        statusText = "连接失败"
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        isConnected = false
        statusText = "连接已断开"
        txChar = nil
        rxChar = nil
        for c in writeContinuations { c.resume(throwing: NBError.notConnected) }
        writeContinuations.removeAll()
        onDisconnect?(error)
    }
}

extension BLEClient: CBPeripheralDelegate {

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        if let e = error {
            serviceContinuation?.resume(throwing: e)
            serviceContinuation = nil
            return
        }
        guard let svc = peripheral.services?.first(where: { $0.uuid.uuidString.lowercased() == NB.svcUART }) else {
            serviceContinuation?.resume(throwing: NBError.handshake("没有找到九号 Legacy UART Service"))
            serviceContinuation = nil
            return
        }
        peripheral.discoverCharacteristics(nil, for: svc)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        if let e = error {
            serviceContinuation?.resume(throwing: e)
            serviceContinuation = nil
            return
        }
        for c in service.characteristics ?? [] {
            let uuid = c.uuid.uuidString.lowercased()
            if uuid == NB.charTX { txChar = c }
            if uuid == NB.charRX { rxChar = c }
        }
        guard txChar != nil, rxChar != nil else {
            serviceContinuation?.resume(throwing: NBError.handshake("缺少 0002/0003 特征"))
            serviceContinuation = nil
            return
        }
        peripheral.setNotifyValue(true, for: rxChar!)
        serviceContinuation?.resume()
        serviceContinuation = nil
        statusText = "通道已就绪"
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        if let e = error { statusText = "开启通知失败：\(e.localizedDescription)" }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard error == nil, let data = characteristic.value, !data.isEmpty else { return }
        onNotification?(data)
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        guard !writeContinuations.isEmpty else { return }
        let cont = writeContinuations.removeFirst()
        if let e = error { cont.resume(throwing: e) } else { cont.resume() }
    }
}
