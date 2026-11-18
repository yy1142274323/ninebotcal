#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NinebotCal 命令行工具（Windows / macOS 可用，需 BLE 适配器）
pip install bleak

用法:
  python ninebot_cli.py scan
  python ninebot_cli.py read  --mac AA:BB:CC:DD:EE:FF --pwd 你的16位密码
  python ninebot_cli.py write --mac ... --pwd ... --profile 0x63     # 高级：直接写档位字节
  python ninebot_cli.py write --mac ... --pwd ... --voltage 60       # 保留容量槽位，只改电压
"""
import argparse
import asyncio
import sys

import ninebot_proto as nb
from ninebot_proto import (
    Crypto, PRE_COMM, REG, CMD_ACK, CMD_PRECOMM, DST_DIS,
    auth_frame, dis_write_frame, le16, make_profile, parse,
    profile_capacity, profile_voltage, read_frame,
)

SVC = nb.SVC_UART
TX = nb.CHAR_TX
RX = nb.CHAR_RX


class Link:
    def __init__(self, client):
        self.client = client
        self.inbox = asyncio.Queue()

    def _notify(self, _char, data: bytearray):
        self.inbox.put(bytes(data))

    async def start(self):
        await self.client.start_notify(nb.CHAR_RX, self._notify)

    async def send(self, data: bytes):
        n = self.client.mtu_size - 3 if self.client.mtu_size > 23 else 20
        for i in range(0, len(data), n):
            await self.client.write_gatt_char(nb.CHAR_TX, data[i:i + n], response=True)

    async def recv(self, timeout=4.0):
        return await asyncio.wait_for(self.inbox.get(), timeout)


async def handshake(link, password):
    c = Crypto(password)
    await link.send(c.enc1(PRE_COMM))
    raw = await link.recv(8)
    plain = c.dec1(raw)
    if len(plain) < 37 or plain[5] != nb.CMD_PRECOMM:
        raise SystemExit("PRE_COMM 回复异常: %s" % plain.hex())
    auth = plain[7:23]
    sn = plain[23:37]
    print("SN:", sn.decode("ascii", "ignore"), " status=0x%02X" % plain[6])
    c.establish(auth)
    await link.send(c.enc2(2, auth_frame(sn)))
    pkt, ctr, ok = c.dec2(await link.recv(8))
    print("AUTH reply ctr=%d mac=%s" % (ctr, "OK" if ok else "FAIL"))
    return c, sn


async def read_all(link, c, counter):
    out = {}
    for name, (dst, reg, ln) in REG.items():
        f = read_frame(name)
        await link.send(c.enc2(counter, f))
        counter += 1
        try:
            pkt, ctr, ok = c.dec2(await link.recv(3))
        except asyncio.TimeoutError:
            print("%-14s 无回复" % name)
            continue
        counter = max(counter, ctr + 1)
        data = parse(pkt, expect_src=dst, expect_cmd=CMD_ACK, expect_reg=reg)
        v = data[0] if ln == 1 else le16(data)
        out[name] = v
        extra = ""
        if name == "dis_profile":
            extra = "  -> %sV / %dAh" % (profile_voltage(v), profile_capacity(v) // 1000)
        print("%-14s 0x%02X/0x%02X = %-6d%s" % (name, dst, reg, v, extra))
    return out, counter


async def async_main(args):
    from bleak import BleakClient, BleakScanner

    if args.cmd == "scan":
        devs = await BleakScanner.discover(timeout=args.timeout)
        for d in devs:
            print("%-40s %-18s %s" % (d.name or "?", d.address, d.rssi))
        return

    print("连接 %s ..." % args.mac)
    async with BleakClient(args.mac, timeout=15) as client:
        link = Link(client)
        await link.start()
        c, sn = await handshake(link, args.pwd)
        values, counter = await read_all(link, c, 3)

        if args.cmd == "write":
            current = values.get("dis_profile")
            if current is None:
                raise SystemExit("读不到当前档位，拒绝写入")
            if args.profile is not None:
                target = int(args.profile, 0)
            elif args.voltage is not None:
                target = make_profile(current, args.voltage)
            else:
                raise SystemExit("需要 --profile 或 --voltage")
            print("写入 0x%02X -> 0x%02X" % (current, target))
            await link.send(c.enc2(counter, dis_write_frame(target)))
            counter += 1
            try:
                await link.recv(4)
            except asyncio.TimeoutError:
                print("写入 ACK 超时（继续回读）")
            for i in range(4):
                await asyncio.sleep(0.45)
                await link.send(c.enc2(counter, read_frame("dis_profile")))
                counter += 1
                pkt, ctr, ok = c.dec2(await link.recv(3))
                counter = max(counter, ctr + 1)
                data = parse(pkt, expect_src=nb.DST_DIS, expect_cmd=CMD_ACK, expect_reg=0x92)
                v = le16(data)
                print("回读 %d/4: 0x%02X" % (i + 1, v))
                if v == target:
                    print("✅ 写入已确认")
                    return
            print("⚠️ 回读未确认，请重新连接读取当前参数，勿连续重复写入")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--timeout", type=float, default=8)
    for name in ("read", "write"):
        p = sub.add_parser(name)
        p.add_argument("--mac", required=True)
        p.add_argument("--pwd", required=True, help="16 位 BLE 密码")
        p.add_argument("--profile", help="目标档位字节，如 0x63")
        p.add_argument("--voltage", type=int, choices=[48, 60, 72])
    args = ap.parse_args()
    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
