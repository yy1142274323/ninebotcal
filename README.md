# NinebotCal — 九号电动车「电量校准」iOS 版

把酷安上 **BFG电量校准 5.0.35** 的核心功能搬到 iPhone：直连车辆，读寄存器，改**仪表盘档位字节（0x92）**，让换过电池 / 改过电压的车显示正确电量。

- 目标系统：iOS 16+，**越狱设备 + TrollStore**（用 TrollStore 装 IPA，不需要 Apple 开发者账号）
- 依赖：CoreBluetooth、CommonCrypto、SQLite3，无第三方库
- 协议与加密：从 BFG 的 `classes.dex`（`Lu2.o` / `Lu2.h` / `Lu2.i`）逐条还原，不是猜的

> ⚠️ 先说清楚：这份 Swift 代码是**按反汇编结果一比一复刻**的，逻辑自洽（Python 参考实现已通过加解密自检），但**没有在真机上编译运行过**（当前环境没有 macOS/Xcode）。第一次使用请先只跑「读取」，确认能读到 SN 和档位，再考虑写入。

---

## 1. 它在做什么（原理）

“电量校准”并不是算法校准，而是**改写仪表盘里的电压/容量档位字节**：

```
仪表盘 0x92 寄存器（2 字节）＝ [profile, 0x00]
    profile 低 4 位：电压   1 = 72V, 2 = 60V, 3 = 48V
    profile 高 4 位：容量槽位（表见下）
```

原车按标称电压估算 SOC/续航；换过 60V 电池却还是 48V 档位，表显就会错。写入正确档位后，表显就对了。

容量槽位表（来自 dex 静态数组 `u2.i;->a`，单位 mAh）：

| 槽位 | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|---|
| 容量 | 20000 | 10500 | 18000 | 36000 | 10500 | 26000 | 14000 | 38000 |

| 槽位 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
|---|---|---|---|---|---|---|---|---|
| 容量 | 13000 | 22000 | 39000 | 45000 | 46000 | 55000 | 52000 | 18000 |

## 2. 协议（还原结果）

BLE 走 **Nordic UART**（九号叫「Legacy UART Service」）：

```
Service 6e400001-b5a3-f393-e0a9-e50e24dcca9e
Write   6e400002-…      Notify 6e400003-…
```

明文帧：

```
5A A5 | LEN | SRC | DST | CMD | REG | DATA[LEN]
```

| 字段 | 含义 |
|---|---|
| SRC/DST | `0x3E` 手机、`0x01` 中控、`0x09` 计量模块、`0x10` 仪表盘 |
| CMD | `0x01` 读、`0x02` 写、`0x04` 应答、`0x5B` PRE_COMM、`0x5D` AUTH |

握手：

1. `PRE_COMM = 5AA5003E045B00`，用 **Enc1** 加密
2. 车回 `5A A5 1E 04 3E 5B <flag> <authParam:16> <SN:14>`
3. `Enc2Key = SHA1(pwd16 ‖ authParam16)[:16]`
4. `AUTH = 5AA50E3E045D00 + SN(14)`，用 **Enc2**、counter 从 2 开始

加密：

```
Enc1: key1 = SHA1(pwd16 ‖ 97CFB802844143DE56002B3B34780A5D)[:16]
      pad  = AES-128-ECB(key1, 97CF…0A5D)          // 16 字节，循环异或
      frame = 5A A5 LEN ‖ payload⊕pad ‖ 00 00 CS_lo CS_hi 00 00
      CS    = ~(Σ payload) & 0xFFFF

Enc2: iv    = 00 00 CTR_hi CTR_lo authParam[0:8] 00        (13B)
      ks_r  = AES-ECB(key2, 01 ‖ iv ‖ 00 ‖ r)              (r=1,2,3…)
      mac   = CBC-MAC(key2, 59 ‖ iv ‖ 00 ‖ len → payload 分块) ⊕ AES-ECB(key2, 01‖iv‖00‖00)[:4]
      frame = 5A A5 LEN ‖ payload⊕ks ‖ mac[4] ‖ CTR_hi CTR_lo
```

写入仪表盘档位：

```
5A A5 02 3E 01 02 92 <profile> 00
```

## 3. 目录

```
NinebotCal/
  Crypto.swift            SHA1 / AES-128-ECB(CommonCrypto)
  NinebotProtocol.swift   帧、常量、寄存器表、Enc1/Enc2
  BLEClient.swift         CoreBluetooth 扫描/连接/收发
  Session.swift           握手、读写、回读校验、恢复
  CredentialStore.swift   Keychain + 越狱读取九号 App 的 device-db
  ContentView.swift       SwiftUI 三个页签
  NinebotCalApp.swift     入口
  Info.plist / NinebotCal.entitlements
project.yml               XcodeGen 工程描述
.github/workflows/build.yml  GitHub Actions 直接出未签名 IPA
tools/ninebot_proto.py    协议参考实现（可跑，带自检）
tools/ninebot_cli.py      命令行工具（Windows/macOS + bleak）
tools/aes.py              纯 Python AES-128（自检用）
```

## 4. 构建

### 路线 A：GitHub Actions（没有 Mac 也能出 IPA）

1. 新建一个仓库，把本目录（`project.yml` 所在层）推上去
2. Actions → `build-ipa` → Run workflow
3. 跑完在 Artifacts 里下载 `NinebotCal-ipa`，得到未签名的 `NinebotCal.ipa`

### 路线 B：本地 Mac

```bash
brew install xcodegen
xcodegen generate
open NinebotCal.xcodeproj      # 选自己的设备/模拟器，改签名后 Run
```

## 5. 安装（TrollStore）

把 `NinebotCal.ipa` 传到手机 → 用 TrollStore 打开 → Install。

- TrollStore 会用 `platform-application` 重新签名，配合 `NinebotCal.entitlements` 里的 `com.apple.private.security.no-sandbox`，App 才有机会读别的 App 沙盒。
- 如果导入凭据失败也**不影响主体功能**：手输 16 位密码即可。

## 6. 密码从哪来

官方 App 把 BLE 密码存在 SQLite 的 `DEVICE` 表（`mac_address` / `password` / `sn`）。

| 方式 | 说明 |
|---|---|
| A. 本 App 自动导入 | 「设置 → 从九号出行沙盒导入」，遍历 `/var/mobile/Containers/Data/Application/*`，按 `MCMMetadataIdentifier` 找 ninebot 容器，再扫 `*.sqlite/*.db` 里的 `DEVICE` 表 |
| B. 手动 | 用 Filza 找到九号 App 的数据库，用 SQLite 编辑器看 `DEVICE` 表，抄 `mac_address` + `password` |
| C. 从安卓来 | 用 BFG 那台机器导出（它自己有 Root/容器两条路），或 `adb backup` 后解 `device-db` |

> 密码是 16 位 ASCII。App 里显示长度，不足 16 会直接拒绝握手。

## 7. 使用流程

1. 关掉主机上的九号出行（避免占用蓝牙），车辆开机、靠近手机
2. 「连接」→ 扫描 → 点你的车 → 自动 PRE_COMM/AUTH → 自动读取全部寄存器
3. 核对界面上的 **SN**、当前档位、仪表版本
4. 「校准」→ 选 48/60/72V（可选改容量槽位）→「写入并回读校验」
5. 弹窗里读完风险、勾选确认 → 写入
6. 结果页会给出 `写入前 / 目标 / 回读 / 结论`；未确认就重新连接读一次，**不要连点**
7. 想还原：「备份」里的「恢复原档位」

## 8. 风险（与 BFG 原版提示一致，不是我加的）

- 仪表盘档位是**持久写入**，断电不还原
- 已有「写入后计量模块损坏」的实车案例，可能导致无法启动、显示异常
- 备份不保证在硬件异常后还能恢复；换新计量模块后仪表可能再次下发旧配置
- 原版还有一道闸门：四项固件必须匹配（仪表控制器 2.5.9 / 彩屏仪表 1.5.5 / 中控 5.12.10 / 计量模块 4.2.9）。**本 App 没有实现这道校验**，请自行核对固件版本再写
- 原版对 SN 以 `N` 开头的车型只读；本 App 也做了同样的拦截

## 9. 和 BFG 原版的差距

| 能力 | BFG 安卓 | 本 App |
|---|---|---|
| 读寄存器 / 导出诊断 | ✅ | ✅ |
| 仪表盘 0x92 档位写入 + 回读 | ✅ | ✅ |
| 备份 / 恢复 | ✅ | ✅（单次备份） |
| 计量模块 0x1C 容量写入 | ✅（临时生效） | ❌ 未实现，帧格式还没完全确认 |
| 四项固件闸门 | ✅ | ❌ 需人工核对 |
| 免账号的临时密钥配对 | ✅ | ❌ 需要 DB 里的密码 |
| 兼容容量扫描（0E/0F/1A/1C/1E 互校） | ✅ | ❌ |

## 10. 先用电脑验证协议（可选，强烈建议）

Windows/macOS 有蓝牙适配器就能跑，比在手机上试错安全：

```bash
pip install bleak
cd tools
python ninebot_cli.py scan
python ninebot_cli.py read  --mac AA:BB:CC:DD:EE:FF --pwd 0123456789abcdef
python ninebot_cli.py write --mac AA:BB:CC:DD:EE:FF --pwd 0123456789abcdef --voltage 60
```

`ninebot_proto.py` 单独跑会做一次加解密自检（Enc1/Enc2 往返、MAC 校验）。

## 11. 排错

| 现象 | 处理 |
|---|---|
| 扫不到车 | 车辆开机、靠近；关掉官方 App；iOS 蓝牙权限已给 |
| 连上但 PRE_COMM 无回复 | 密码错（16 位？）、车被别的手机占用、或该车用的是新版协议 |
| AUTH 无回复 | 会话密钥不对，通常是 authParam 解析位置偏了 —— 把日志发我 |
| 写入 ACK 无回复 | 别重试，重新连接读一次当前档位 |
| 导入凭据读不到数据库 | 沙盒权限没给到；改用 Filza 手抄密码 |

---

协议逆向来源：`BFG电量校准 5.0.35`（`com.bfgtools.calibration.imported`，versionCode 535），
`classes.dex` 中 `Lu2.o`（加解密）、`Lu2.h`（BLE 状态机）、`Lu2.i`（档位/容量表）。
