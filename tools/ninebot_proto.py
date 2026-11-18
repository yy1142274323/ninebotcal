#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ninebot (九号) legacy UART-over-BLE protocol + BFG 'DIS profile' calibration.
Protocol and crypto reconstructed from BFG电量校准 5.0.35 classes.dex (classes u2.o / u2.h / u2.i).

Frame layout (plain):
    5A A5 | LEN | SRC | DST | CMD | REG | DATA[LEN]

  CMD 0x01 read, 0x02 write, 0x04 response, 0x5B PRE_COMM, 0x5D AUTH
  SRC 0x3E = phone, 0x01 = 中控, 0x09 = 计量模块, 0x10 = 仪表盘(DIS)

Encryption:
  Enc1 (pre-auth):  key1 = SHA1(pwd16 || KEY0)[:16]
                    ct   = payload XOR AES-ECB(key1, KEY0)   (16-byte repeating pad)
                    frame = 5A A5 LEN || ct || 00 00 CS_lo CS_hi 00 00
                    CS   = ~sum(payload) & 0xFFFF              (payload = plain[3:])
  Enc2 (session):   key2 = SHA1(pwd16 || authParam16)[:16]
                    iv   = 00 00 CTR_hi CTR_lo authParam[0:8] 00      (13 bytes)
                    ks_r = AES-ECB(key2, 01 || iv || 00 || r)          (r = 1,2,3..)
                    ct   = payload XOR ks (16-byte blocks)
                    mac  = CBCMAC(key2, 59 || iv || 00 || len) then chain payload blocks,
                           XOR AES-ECB(key2, 01 || iv || 00 || 00)[:4]
                    frame = 5A A5 LEN || ct || mac[4] || CTR_hi || CTR_lo
"""
import hashlib
import hmac
import os
import struct

SVC_UART = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
CHAR_TX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
CHAR_RX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"

KEY0 = bytes.fromhex("97CFB802844143DE56002B3B34780A5D")  # Lu2/o;->e  (default key)

SRC_PHONE = 0x3E
DST_MAIN = 0x01      # 中控
DST_METER = 0x09     # 计量模块
DST_DIS = 0x10       # 仪表盘

CMD_READ = 0x01
CMD_WRITE = 0x02
CMD_ACK = 0x04
CMD_PRECOMM = 0x5B
CMD_AUTH = 0x5D

PRE_COMM = bytes.fromhex("5AA5003E045B00")

# 仪表盘(DIS) / 中控 / 计量模块 寄存器
REG = {
    "dis_soc":        (DST_DIS, 0x00, 1),
    "dis_misc":       (DST_DIS, 0x02, 1),
    "dis_capacity":   (DST_DIS, 0x1C, 2),
    "dis_profile":    (DST_DIS, 0x92, 2),   # 电压/容量档位字节 + 0x00
    "vrla_voltage":   (DST_MAIN, 0xB1, 2),
    "battery":        (DST_MAIN, 0xB5, 2),
    "bfg_version":    (DST_MAIN, 0x3D, 2),  # rBFGV
    "dash_version":   (DST_MAIN, 0x1A, 2),
    "d1":             (DST_MAIN, 0xD1, 2),
    "e1":             (DST_MAIN, 0x1E, 2),
    "reg44":          (DST_MAIN, 0x44, 2),
    "meter_ver":      (DST_METER, 0x02, 2),
}

# 容量槽位表 (i.a)，索引 = profile 高半字节，单位 mAh
CAPACITY_SLOTS = [
    20000, 10500, 18000, 36000, 10500, 26000, 14000, 38000,
    13000, 22000, 39000, 45000, 46000, 55000, 52000, 18000,
]
# 电压档位低半字节编码 (i.k / i.s): 1=72V, 2=60V, 3=48V
VOLT_CODE = {72: 1, 60: 2, 48: 3}
VOLT_DECODE = {1: 72, 2: 60, 3: 48, 0: 72}


def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        c = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return c.update(data) + c.finalize()
    except Exception:
        from aes import encrypt_block
        assert len(data) == 16, "pure-python path is single-block only"
        return encrypt_block(key, data)


def pad16(b: bytes) -> bytes:
    return (b + b"\x00" * 16)[:16]


def sha1(*parts: bytes) -> bytes:
    h = hashlib.sha1()
    for p in parts:
        h.update(p)
    return h.digest()


class Crypto:
    def __init__(self, password: str):
        pwd = password.encode("ascii", "ignore")
        self.pwd16 = pad16(pwd)
        self.key1 = sha1(self.pwd16, KEY0)[:16]      # Enc1
        self.pad1 = aes_ecb_encrypt(self.key1, KEY0)
        self.key2 = None                              # Enc2, set by establish()
        self.auth_param = None

    # ---------- Enc1 ----------
    def enc1(self, plain: bytes) -> bytes:
        payload = plain[3:]
        ct = bytes(b ^ self.pad1[i & 15] for i, b in enumerate(payload))
        cs = (~sum(payload)) & 0xFFFF
        return plain[:3] + ct + bytes([0, 0, cs & 0xFF, (cs >> 8) & 0xFF, 0, 0])

    def dec1(self, frame: bytes) -> bytes:
        payload = frame[3:len(frame) - 6]
        pt = bytes(b ^ self.pad1[i & 15] for i, b in enumerate(payload))
        return frame[:3] + pt

    # ---------- Enc2 ----------
    def establish(self, auth_param: bytes):
        self.auth_param = auth_param
        self.key2 = sha1(self.pwd16, pad16(auth_param))[:16]

    def _iv(self, counter: int) -> bytes:
        return bytes([0, 0, (counter >> 8) & 0xFF, counter & 0xFF]) + self.auth_param[:8] + b"\x00"

    def _keystream_block(self, counter: int, r: int) -> bytes:
        return aes_ecb_encrypt(self.key2, bytes([0x01]) + self._iv(counter) + bytes([0, r & 0xFF]))

    def _crypt(self, counter: int, data: bytes) -> bytes:
        out = bytearray()
        for i in range(0, len(data), 16):
            ks = self._keystream_block(counter, i // 16 + 1)
            for j, b in enumerate(data[i:i + 16]):
                out.append(b ^ ks[j])
        return bytes(out)

    def _mac(self, counter: int, plain: bytes) -> bytes:
        payload = plain[3:]
        iv = self._iv(counter)
        first = aes_ecb_encrypt(self.key2, bytes([0x59]) + iv + bytes([0, len(payload) & 0xFF]))
        hdr = pad16(plain[:3])
        chain = aes_ecb_encrypt(self.key2, bytes(a ^ b for a, b in zip(first, hdr)))
        for i in range(0, len(payload), 16):
            block = pad16(payload[i:i + 16])
            chain = aes_ecb_encrypt(self.key2, bytes(a ^ b for a, b in zip(chain, block)))
        tail = aes_ecb_encrypt(self.key2, bytes([0x01]) + iv + b"\x00\x00")
        return bytes(a ^ b for a, b in zip(chain[:4], tail[:4]))

    def enc2(self, counter: int, plain: bytes) -> bytes:
        ct = self._crypt(counter, plain[3:])
        mac = self._mac(counter, plain)
        return plain[:3] + ct + mac + bytes([(counter >> 8) & 0xFF, counter & 0xFF])

    def dec2(self, frame: bytes):
        """returns (plain, counter, mac_ok)"""
        counter = (frame[-2] << 8) | frame[-1]
        ct = frame[3:len(frame) - 6]
        mac = frame[len(frame) - 6:len(frame) - 2]
        plain = frame[:3] + self._crypt(counter, ct)
        return plain, counter, hmac.compare_digest(mac, self._mac(counter, plain))


# ---------- frame helpers ----------
def frame(dst: int, cmd: int, reg: int, data: bytes = b"") -> bytes:
    return bytes([0x5A, 0xA5, len(data), SRC_PHONE, dst, cmd, reg]) + data


def read_frame(name_or_reg, dst=None, ln=None) -> bytes:
    if isinstance(name_or_reg, str):
        dst, reg, ln = REG[name_or_reg]
    else:
        reg = name_or_reg
    return frame(dst, CMD_READ, reg, bytes([ln]))


def auth_frame(sn: bytes) -> bytes:
    assert len(sn) == 14, "SN must be 14 bytes"
    return bytes.fromhex("5AA50E3E045D00") + sn


def dis_write_frame(profile: int) -> bytes:
    """仪表盘 0x92 写入: LEN=2, DST=0x01, CMD=0x02, REG=0x92, DATA=[profile,0]"""
    return frame(DST_MAIN, CMD_WRITE, 0x92, bytes([profile & 0xFF, 0x00]))


def parse(frame_bytes: bytes, expect_src=None, expect_cmd=CMD_ACK, expect_reg=None):
    assert len(frame_bytes) >= 7, "short frame"
    if frame_bytes[0] != 0x5A or frame_bytes[1] != 0xA5:
        raise ValueError("bad header %s" % frame_bytes[:2].hex())
    ln, src, dst, cmd, reg = frame_bytes[2], frame_bytes[3], frame_bytes[4], frame_bytes[5], frame_bytes[6]
    if expect_src is not None and src != expect_src:
        raise ValueError("src 0x%02X != 0x%02X" % (src, expect_src))
    if cmd != expect_cmd:
        raise ValueError("cmd 0x%02X != 0x%02X" % (cmd, expect_cmd))
    if expect_reg is not None and reg != expect_reg:
        raise ValueError("reg 0x%02X != 0x%02X" % (reg, expect_reg))
    data = frame_bytes[7:7 + ln]
    if len(data) != ln:
        raise ValueError("truncated payload")
    return data


def le16(data: bytes) -> int:
    return data[0] | (data[1] << 8)


def profile_voltage(p: int) -> int:
    return VOLT_DECODE.get(p & 0x0F, -1)


def profile_capacity(p: int) -> int:
    return CAPACITY_SLOTS[(p >> 4) & 0x0F]


def make_profile(current: int, voltage: int, capacity_mah=None) -> int:
    """保留(或替换)容量高半字节，设置电压低半字节"""
    if voltage not in VOLT_CODE:
        raise ValueError("不支持的电压档位: %r" % voltage)
    hi = (current >> 4) & 0x0F
    if capacity_mah is not None:
        if capacity_mah not in CAPACITY_SLOTS:
            raise ValueError("容量 %d 不在档位表内: %s" % (capacity_mah, CAPACITY_SLOTS))
        hi = CAPACITY_SLOTS.index(capacity_mah)
    return ((hi << 4) | VOLT_CODE[voltage]) & 0xFF


# ---------- self test ----------
if __name__ == "__main__":
    c = Crypto("1234567890abcdef")
    sn = b"9" * 14
    print("key1      ", c.key1.hex())
    print("pad1      ", c.pad1.hex())
    print("PRE_COMM  ", c.enc1(PRE_COMM).hex())
    # fake vehicle reply: 5A A5 1E 04 3E 5B 01 <auth16> <sn14>
    auth = bytes(range(16))
    reply = bytes([0x5A, 0xA5, 30, 0x04, 0x3E, 0x5B, 0x01]) + auth + sn
    enc = c.enc1(reply)
    dec = c.dec1(enc)
    assert dec == reply, "Enc1 roundtrip failed"
    print("Enc1 roundtrip ok, reply len", len(enc))
    c.establish(auth)
    print("key2      ", c.key2.hex())
    pkt = auth_frame(sn)
    e2 = c.enc2(2, pkt)
    p2, ctr, ok = c.dec2(e2)
    print("AUTH frame", e2.hex())
    assert p2 == pkt and ctr == 2 and ok, "Enc2 roundtrip failed"
    print("Enc2 roundtrip ok")
    r = read_frame("dis_profile")
    print("read 0x92 ", r.hex(), "->", c.enc2(3, r).hex())
    w = dis_write_frame(0x63)
    print("write 0x92", w.hex(), "->", c.enc2(4, w).hex())
    print("profile 0x63 => %dV, %dmAh" % (profile_voltage(0x63), profile_capacity(0x63)))
    print("make_profile(0x62, 48) = 0x%02X" % make_profile(0x62, 48))
